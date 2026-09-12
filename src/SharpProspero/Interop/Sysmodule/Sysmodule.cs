// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Sysmodule;

/// <summary>Identifiers for the loadable system modules an application can bring in at run time.</summary>
public enum SystemModuleId : ushort
{
    /// <summary>Performance counters.</summary>
    Perf = 0x0005,

    /// <summary>Fibers.</summary>
    Fiber = 0x0006,

    /// <summary>User-level threading.</summary>
    Ult = 0x0007,

    /// <summary>Audio mixing and synthesis.</summary>
    Ngs2 = 0x000B,

    /// <summary>XML parsing.</summary>
    Xml = 0x0017,

    /// <summary>Voice chat.</summary>
    Voice = 0x001A,

    /// <summary>Voice quality of service.</summary>
    VoiceQos = 0x001B,

    /// <summary>Reliable UDP.</summary>
    Rudp = 0x0021,

    /// <summary>Chunk streaming.</summary>
    PlayGo = 0x0083,

    /// <summary>Font rasterization.</summary>
    Font = 0x0084,

    /// <summary>Audio decoding.</summary>
    AudioDec = 0x0088,

    /// <summary>JPEG decoding.</summary>
    JpegDec = 0x008A,

    /// <summary>JPEG encoding.</summary>
    JpegEnc = 0x008B,

    /// <summary>PNG decoding.</summary>
    PngDec = 0x008C,

    /// <summary>PNG encoding.</summary>
    PngEnc = 0x008D,

    /// <summary>FreeType font support.</summary>
    FontFt = 0x0098,

    /// <summary>The FreeType OpenType backend the font renderer draws glyphs through. It must be
    /// loaded alongside <see cref="Font"/> and <see cref="FontFt"/> before a scalable font is created;
    /// without it the renderer reaches an unresolved glyph routine and the process faults.</summary>
    FreeTypeOt = 0x0099,

    /// <summary>Audio/video playback.</summary>
    AvPlayer = 0x00A5,

    /// <summary>The on-screen keyboard dialog.</summary>
    ImeDialog = 0x0096,

    /// <summary>The message dialog (progress bar, yes/no, system messages).</summary>
    MessageDialog = 0x00A4,

    /// <summary>The system web browser dialog.</summary>
    WebBrowserDialog = 0x00AB,

    /// <summary>The error dialog.</summary>
    ErrorDialog = 0x00AC,

    /// <summary>3D audio.</summary>
    Audio3d = 0x00A7,

    /// <summary>Mouse input.</summary>
    Mouse = 0x00A9,

    /// <summary>Additional-content access.</summary>
    AppContent = 0x00B4,

    /// <summary>Content deletion (captures and other content).</summary>
    ContentDelete = 0x00EE,

    /// <summary>Content search (the library of captures and imported media).</summary>
    ContentSearch = 0x00C7,

    /// <summary>Content export (copy a file into the content library).</summary>
    ContentExport = 0x00A6,

    /// <summary>The save-data dialog (list, confirm and report on saves).</summary>
    SaveDataDialog = 0x00A0,

    /// <summary>Random-number service.</summary>
    Random = 0x00BA,

    /// <summary>AAC encoding.</summary>
    M4aacEnc = 0x00BC,

    /// <summary>CPU audio decoding.</summary>
    AudioDecCpu = 0x00BD,

    /// <summary>Screenshot and video-clip capture.</summary>
    Share = 0x010F,
}

/// <summary>
/// System-module loader bindings. Several device libraries are not resident by default; a module
/// loads the ones it needs by identifier before calling into them, and unloads them when finished.
/// </summary>
public static unsafe partial class Sysmodule
{
    private const string Lib = "libSceSysmodule";

    /// <summary>Loads the module with <paramref name="id"/>. Zero on success, or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSysmoduleLoadModule(ushort id);

    /// <summary>Unloads the module with <paramref name="id"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSysmoduleUnloadModule(ushort id);

    /// <summary>Reports whether the module with <paramref name="id"/> is loaded (zero when loaded).</summary>
    [LibraryImport(Lib)]
    public static partial int sceSysmoduleIsLoaded(ushort id);

    /// <summary>
    /// Loads a system module by its internal identifier (with the <c>0x80000000</c> mask).
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSysmoduleLoadModuleInternal(uint id);

    /// <summary>
    /// Unloads a system module by its internal identifier.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSysmoduleUnloadModuleInternal(uint id);

    /// <summary>
    /// Loads a system module by its SPRX filename.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSysmoduleLoadModuleByNameInternal(byte* fname,
        ulong a1, ulong a2, ulong a3, ulong a4, ulong a5);
}
