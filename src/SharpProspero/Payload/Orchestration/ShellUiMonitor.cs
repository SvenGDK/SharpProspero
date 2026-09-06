// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.IO;
using SharpProspero.Payload.Kernel;
using SharpProspero.Payload.Posix;
using SharpProspero.Payload.Process;

namespace SharpProspero.Payload.Orchestration;

/// <summary>
/// Monitors for new shell UI process instances via kqueue and re-applies patches
/// after rest-mode resume or process restart.
/// </summary>
public static unsafe class PayloadShellUiMonitor
{
    /// <summary>
    /// Starts a persistent monitoring loop that watches for new shell UI instances
    /// via kqueue EVFILT_PROC NOTE_FORK/NOTE_EXEC on the system core process.
    /// When a new instance is detected, applies the trophy availability patch.
    /// Runs indefinitely — call on a background thread.
    /// </summary>
    /// <param name="io">Kernel I/O for process inspection.</param>
    /// <param name="sysCorePid">PID of the system core process to monitor.</param>
    /// <param name="dmapBase">DMAP base for physical memory access.</param>
    /// <param name="fwMajorMinor">Firmware major.minor for vmspace offset lookup.</param>
    public static void Run(PayloadKernelIo io, int sysCorePid, ulong dmapBase, uint fwMajorMinor)
    {
        int kq = PayloadEvent.kqueue();
        if (kq < 0) return;

        // Register for fork/exec/track events on SceSysCore.elf with EV_CLEAR so
        // the event is re-armed after each delivery. NOTE_TRACK follows forked
        // children, delivering NOTE_EXEC on the child's PID when it calls exec.
        FreeBsdKevent ev = default;
        PayloadEvent.EvSet(&ev, (nuint)sysCorePid, PayloadEvent.EvfiltProc,
            (ushort)(PayloadEvent.EvAdd | PayloadEvent.EvEnable | PayloadEvent.EvClear),
            PayloadEvent.NoteFork | PayloadEvent.NoteExec | PayloadEvent.NoteTrack,
            0, null);

        if (PayloadEvent.kevent(kq, &ev, 1, null, 0, null) < 0)
        {
            PayloadIo.close(kq);
            return;
        }

        while (true)
        {
            FreeBsdKevent fired = default;
            int n = PayloadEvent.kevent(kq, null, 0, &fired, 1, null);
            if (n == 0) continue;

            if (n < 0)
            {
                PayloadIo.close(kq);
                return;
            }

            // Only act on exec events (the child called execve).
            if ((fired.fflags & PayloadEvent.NoteExec) == 0)
                continue;

            // The event ident carries the PID of the process that exec'd.
            int newPid = (int)fired.ident;

            // Verify the process is SceShellUI by checking its title ID.
            PayloadAppInfo appInfo = default;
            if (PayloadProcess.sceKernelGetAppInfo(newPid, &appInfo) != 0)
                continue;

            bool isShellUi = appInfo.TitleId[0] == (byte)'N'
                && appInfo.TitleId[1] == (byte)'P'
                && appInfo.TitleId[2] == (byte)'X'
                && appInfo.TitleId[3] == (byte)'S'
                && appInfo.TitleId[4] == (byte)'4'
                && appInfo.TitleId[5] == (byte)'0'
                && appInfo.TitleId[6] == (byte)'0'
                && appInfo.TitleId[7] == (byte)'8'
                && appInfo.TitleId[8] == (byte)'7';

            if (!isShellUi)
                continue;

            PayloadShellUiPatcher.PatchTrophyChecks(io, newPid, dmapBase, fwMajorMinor);
        }
    }
}
