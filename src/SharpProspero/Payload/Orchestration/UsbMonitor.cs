// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.IO;
using SharpProspero.Payload.Posix;
using SharpProspero.Payload.Process;

namespace SharpProspero.Payload.Orchestration;

/// <summary>
/// USB filesystem change monitor. Watches for USB mount/unmount events via kqueue
/// EVFILT_FS and triggers a title re-scan when media changes are detected.
/// </summary>
public static unsafe class PayloadUsbMonitor
{
    /// <summary>
    /// Starts a persistent monitoring loop that watches for filesystem changes and
    /// triggers <see cref="PayloadTitleAutoMount.ScanAndMountTitles"/> when USB media
    /// is inserted or removed. Runs indefinitely — call on a background thread.
    /// </summary>
    /// <param name="isMounting">Pointer to a bool flag that prevents re-entrant scanning
    /// when the scan's own mount operations trigger EVFILT_FS events.</param>
    public static void Run(bool* isMounting)
    {
        int kq = PayloadEvent.kqueue();
        if (kq < 0) return;

        FreeBsdKevent ev = default;
        PayloadEvent.EvSet(&ev, 0, PayloadEvent.EvfiltFs,
            (ushort)(PayloadEvent.EvAdd | PayloadEvent.EvClear), 0, 0, null);

        if (PayloadEvent.kevent(kq, &ev, 1, null, 0, null) < 0)
        {
            PayloadIo.close(kq);
            return;
        }

        while (true)
        {
            FreeBsdKevent fired = default;
            int n = PayloadEvent.kevent(kq, null, 0, &fired, 1, null);

            if (n < 0) break;
            if (n == 0) continue;

            if (isMounting != null && *isMounting)
                continue;

            PayloadThread.sleep(1);
            PayloadTitleAutoMount.ScanAndMountTitles();
        }

        PayloadIo.close(kq);
    }
}
