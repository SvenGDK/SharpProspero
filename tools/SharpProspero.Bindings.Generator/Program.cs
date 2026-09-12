// SharpProspero.Bindings.Generator - turns the SDK headers into C# interop bindings.
// Copyright (C) 2026 SvenGDK
//
// Two ways to produce bindings. The `prx` command reads a supplied module and emits a wrapper for
// its exports, needing nothing but the module. The `stub` command writes a link stub for a module.
// The header path (no subcommand) writes response files describing a header-to-C# run for external
// processing; it makes no external calls of its own.

using SharpProspero.Link;
using SharpProspero.Prx;
using SharpProspero.Texture;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SharpProspero.Bindings.Generator;

/// <summary>One module in the catalog: the header to parse and how to shape its bindings.</summary>
internal sealed class ModuleSpec
{
    public string Name { get; set; } = "";
    public string Header { get; set; } = "";
    public string Library { get; set; } = "";
    public string MethodClassName { get; set; } = "";
    public string? Namespace { get; set; }
    public string[]? Config { get; set; }
    public string[]? Exclude { get; set; }
    public Dictionary<string, string>? Remap { get; set; }
    public string[]? AdditionalArgs { get; set; }
}

internal sealed class Catalog
{
    public string[]? DefaultConfig { get; set; }
    public string[]? DefaultAdditionalArgs { get; set; }
    public List<ModuleSpec> Modules { get; set; } = [];
}

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly HashSet<string> KnownVerbs = new(StringComparer.Ordinal)
    {
        "prx", "stub", "crt", "compat", "nid", "elf", "self", "offsets", "retarget", "sysver", "link", "kmod", "diff", "gnf", "payload", "shader", "vag",
        "modules", "param",
    };

    private static int Main(string[] args)
    {
        // Report the tool version for a bare `version`, or for `--version` only when no command leads:
        // a leading command may take its own `--version` option (sysver settles a required system
        // version), which must not be shadowed by the global flag.
        bool versionQuery = (args.Length > 0 && string.Equals(args[0], "version", StringComparison.Ordinal))
            || (HasFlag(args, "--version") && (args.Length == 0 || !KnownVerbs.Contains(args[0])));
        if (versionQuery)
        {
            Console.WriteLine(ToolVersion());
            return 0;
        }

        // A help flag prints the usage of the named command when one leads, or the whole list otherwise.
        if (HasFlag(args, "--help") || HasFlag(args, "-h"))
        {
            if (args.Length > 0 && KnownVerbs.Contains(args[0]))
                PrintVerbUsage(args[0]);
            else
                PrintUsage();
            return 0;
        }

        // Bindings can be generated from a supplied module instead of from headers, so a user needs
        // only their own .prx to interact with it.
        if (args.Length > 0 && string.Equals(args[0], "prx", StringComparison.Ordinal))
            return RunPrx(args);

        // Generates a link stub so the linker resolves calls to a module the project supplies.
        if (args.Length > 0 && string.Equals(args[0], "stub", StringComparison.Ordinal))
            return RunStub(args);

        // Writes the start object that carries the program entry point.
        if (args.Length > 0 && string.Equals(args[0], "crt", StringComparison.Ordinal))
            return RunCrt(args);
        if (args.Length > 0 && string.Equals(args[0], "compat", StringComparison.Ordinal))
            return RunCompat(args);

        // Prints the identifier a module export is keyed by, for a plain symbol name.
        if (args.Length > 0 && string.Equals(args[0], "nid", StringComparison.Ordinal))
            return RunNid(args);

        // Prints an ELF module's header, without an external tool.
        if (args.Length > 0 && string.Equals(args[0], "elf", StringComparison.Ordinal))
            return RunElf(args);

        // Checks that every module the application has to carry is in its module folder, and gathers
        // the missing ones when a source folder is given.
        if (args.Length > 0 && string.Equals(args[0], "modules", StringComparison.Ordinal))
            return RunModules(args);

        // Converts between the unsigned (.elf/.prx) and signed (.self/.sprx) forms, and reports which
        // a file is.
        if (args.Length > 0 && string.Equals(args[0], "self", StringComparison.Ordinal))
            return RunSelf(args);

        // Dumps a supplied module's export identifiers and addresses (and, with --coverage, how it
        // covers the names the SDK needs), so a firmware's facts can be contributed.
        if (args.Length > 0 && string.Equals(args[0], "offsets", StringComparison.Ordinal))
            return RunOffsets(args);

        // Rewrites the version a supplied module targets (and, optionally, a library version tag), so a
        // module built for one system can be retargeted to another.
        if (args.Length > 0 && string.Equals(args[0], "retarget", StringComparison.Ordinal))
            return RunRetarget(args);

        // Checks the metadata that describes the application to the system, and completes what a
        // finished title always carries.
        if (args.Length > 0 && string.Equals(args[0], "param", StringComparison.Ordinal))
            return RunParam(args);

        // Settles the system version an application requires against the modules it ships.
        if (args.Length > 0 && string.Equals(args[0], "sysver", StringComparison.Ordinal))
            return RunSysVer(args);

        // Resolves the symbol graph of a set of objects and archives.
        if (args.Length > 0 && string.Equals(args[0], "link", StringComparison.Ordinal))
            return RunLink(args);

        // Generates kernel module ELF blobs as a C# source file (build-time, like the C Makefile).
        if (args.Length > 0 && string.Equals(args[0], "kmod", StringComparison.Ordinal))
            return RunKmod(args);

        // Compares the export surfaces of two modules, across firmware versions.
        if (args.Length > 0 && string.Equals(args[0], "diff", StringComparison.Ordinal))
            return RunDiff(args);

        // Builds a GNF texture from an image file, or reports a GNF's header.
        if (args.Length > 0 && string.Equals(args[0], "shader", StringComparison.Ordinal))
            return RunShader(args);

        if (args.Length > 0 && string.Equals(args[0], "vag", StringComparison.Ordinal))
            return RunVag(args);

        if (args.Length > 0 && string.Equals(args[0], "gnf", StringComparison.Ordinal))
            return RunGnf(args);

        // Sends a built payload to a listening loader over the network.
        if (args.Length > 0 && string.Equals(args[0], "payload", StringComparison.Ordinal))
            return RunPayload(args);

        // A leading token that names no command is a mistyped verb: report it rather than falling through
        // to the header-generation default, which would fail later with an unrelated SDK-path message.
        if (args.Length > 0 && !args[0].StartsWith('-'))
        {
            Console.Error.WriteLine($"Unknown command '{args[0]}'. Run with --help for the list of commands.");
            return 2;
        }

        string toolRoot = AppContext.BaseDirectory;
        string sdkInclude = GetOption(args, "--sdk") ?? DefaultSdkInclude();
        string modulesPath = GetOption(args, "--modules") ?? Path.Combine(toolRoot, "modules.json");
        string outDir = GetOption(args, "--out") ?? DefaultOutputDir();
        string responsesDir = GetOption(args, "--responses") ?? Path.Combine(outDir, "responses");

        if (!Directory.Exists(sdkInclude))
        {
            Console.Error.WriteLine($"SDK include folder not found: {sdkInclude}");
            Console.Error.WriteLine("Pass --sdk <folder> or set PROSPERO_SDK_DIR.");
            return 1;
        }
        if (!File.Exists(modulesPath))
        {
            Console.Error.WriteLine($"Module catalog not found: {modulesPath}");
            return 1;
        }

        Catalog catalog = JsonSerializer.Deserialize<Catalog>(File.ReadAllText(modulesPath), JsonOptions)
                          ?? new Catalog();

        Directory.CreateDirectory(responsesDir);
        Directory.CreateDirectory(outDir);

        int emitted = 0;
        foreach (ModuleSpec module in catalog.Modules)
        {
            string responsePath = Path.Combine(responsesDir, module.Name + ".rsp");
            string response = BuildResponse(module, catalog, sdkInclude, outDir);
            File.WriteAllText(responsePath, response);
            Console.WriteLine($"Wrote {responsePath}");
            emitted++;
        }

        Console.WriteLine();
        Console.WriteLine($"{emitted} response file(s) in {responsesDir}");
        Console.WriteLine("These describe a header-to-C# run for external processing. To generate bindings");
        Console.WriteLine("without the headers, use `prx --module <file.prx> --names <file>`.");
        return 0;
    }

    private static string BuildResponse(ModuleSpec module, Catalog catalog, string sdkInclude, string outDir)
    {
        string headerPath = Path.Combine(sdkInclude, module.Header);
        string ns = string.IsNullOrWhiteSpace(module.Namespace)
            ? $"SharpProspero.Interop.{module.Name}"
            : module.Namespace!;
        string outputFile = Path.Combine(outDir, module.Name, module.Name + ".g.cs");

        var sb = new StringBuilder();
        sb.AppendLine("# Generated by SharpProspero.Bindings.Generator. Edit modules.json, not this file.");
        AppendArg(sb, "--file", headerPath);
        AppendArg(sb, "--output", outputFile);
        AppendArg(sb, "--namespace", ns);
        AppendArg(sb, "--methodClassName", module.MethodClassName);
        AppendArg(sb, "--libraryPath", module.Library);
        AppendArg(sb, "--include-directory", sdkInclude);
        AppendArg(sb, "--traverse", headerPath);

        string[] config = module.Config ?? catalog.DefaultConfig ?? DefaultConfig;
        if (config.Length > 0)
        {
            sb.Append("--config");
            foreach (string token in config)
                sb.Append(' ').Append(token);
            sb.AppendLine();
        }

        if (module.Remap is { Count: > 0 })
        {
            sb.Append("--remap");
            foreach (KeyValuePair<string, string> pair in module.Remap)
                sb.Append(' ').Append(pair.Key).Append('=').Append(pair.Value);
            sb.AppendLine();
        }

        if (module.Exclude is { Length: > 0 })
        {
            sb.Append("--exclude");
            foreach (string name in module.Exclude)
                sb.Append(' ').Append(name);
            sb.AppendLine();
        }

        string[] additional = module.AdditionalArgs ?? catalog.DefaultAdditionalArgs ?? DefaultAdditionalArgs;
        if (additional.Length > 0)
        {
            sb.Append("--additional");
            foreach (string arg in additional)
                sb.Append(' ').Append(arg);
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static void AppendArg(StringBuilder sb, string name, string value)
        => sb.Append(name).Append(' ').Append(Quote(value)).AppendLine();

    private static string Quote(string value)
        => value.Contains(' ', StringComparison.Ordinal) ? "\"" + value + "\"" : value;

    private static string DefaultSdkInclude()
    {
        string? sdk = Environment.GetEnvironmentVariable("PROSPERO_SDK_DIR");
        return string.IsNullOrWhiteSpace(sdk) ? "" : Path.Combine(sdk, "target", "include");
    }

    private static string DefaultOutputDir()
        => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "SharpProspero", "Interop", "Generated"));

    private static readonly string[] DefaultConfig =
    [
        "generate-macro-bindings",
        "generate-file-scoped-namespaces",
        "generate-helper-types",
        "exclude-empty-records",
    ];

    private static readonly string[] DefaultAdditionalArgs =
    [
        "-std=c11",
        "-Wno-pragma-once-outside-header",
    ];

    private static string? GetOption(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.Ordinal))
                return args[i + 1];
        }
        return null;
    }

    private static bool HasFlag(string[] args, string name)
        => Array.Exists(args, a => string.Equals(a, name, StringComparison.Ordinal));

    // Reads an object file into an ElfObject. The start object is fully self-contained: it calls
    // main directly, so no rename or symbol wrapping is needed on the input objects.
    private static ElfObject LoadPayloadObject(string path)
        => ElfObjectReader.Read(File.ReadAllBytes(path), path);

    // Generates bindings from a supplied module. `prx --inspect` lists the exports; `prx --names`
    // emits a wrapper for the named exports and verifies each is present.
    private static int RunPrx(string[] args)
    {
        string? module = GetOption(args, "--module");
        if (string.IsNullOrEmpty(module) || !File.Exists(module))
        {
            Console.Error.WriteLine("Pass --module <file.prx> to a plaintext module.");
            return 1;
        }

        PrxImage image;
        try { image = PrxImage.Load(module); }
        catch (Exception ex) when (ex is PrxFormatException or IOException)
        {
            Console.Error.WriteLine($"Cannot read module: {ex.Message}");
            return 2;
        }

        if (HasFlag(args, "--inspect"))
        {
            Console.WriteLine($"Exports: {image.Exports.Count}");
            foreach (PrxExport export in image.Exports)
                Console.WriteLine($"  {export.Nid}  lib={export.LibraryId} mod={export.ModuleId} {(export.IsFunction ? "func" : "data")} {export.LibraryName}");
            return 0;
        }

        string? namesPath = GetOption(args, "--names");
        if (string.IsNullOrEmpty(namesPath) || !File.Exists(namesPath))
        {
            Console.Error.WriteLine("Pass --names <file> (one export per line), or --inspect to list exports.");
            return 1;
        }

        string moduleFileName = GetOption(args, "--module-name") ?? Path.GetFileName(module);
        string className = GetOption(args, "--class") ?? SanitizeIdentifier(Path.GetFileNameWithoutExtension(module));
        string ns = GetOption(args, "--namespace") ?? "SharpProspero.Bindings";

        var bindings = new List<PrxBinding>();
        int missing = 0;
        foreach (string raw in File.ReadAllLines(namesPath))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;
            PrxBinding binding = ParseBinding(line);
            if (image.FindByName(binding.Name) is null)
            {
                Console.Error.WriteLine($"Warning: '{binding.Name}' is not exported by the module.");
                missing++;
            }
            bindings.Add(binding);
        }

        // With --strict a name the module does not export fails the run, so a build script catches a
        // wrapper that would bind a symbol the module cannot resolve. Without it the run still succeeds
        // and only warns, as before.
        if (missing > 0 && HasFlag(args, "--strict"))
        {
            Console.Error.WriteLine($"{missing} requested name(s) are not exported by the module; refusing to emit under --strict.");
            return 3;
        }

        string source = PrxBindingsEmitter.Emit(ns, className, moduleFileName, bindings);
        string? outPath = GetOption(args, "--out");
        if (outPath is null)
        {
            Console.WriteLine(source);
        }
        else
        {
            string full = Path.GetFullPath(outPath);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, source);
            Console.WriteLine($"Wrote {full} ({bindings.Count} bindings, {missing} not found in the module).");
        }
        return 0;
    }

    // Resolves the symbol graph of the given objects and archives and reports it.
    private static int RunLink(string[] args)
    {
        var options = new LinkOptions();
        var exportNames = new List<string>();
        var objectPaths = new List<string>();
        var sprxExtras = new List<string>();
        string? kernelSprx = null;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--obj") objectPaths.Add(args[i + 1]);
            else if (args[i] == "--lib") options.Archives.Add(args[i + 1]);
            else if (args[i] == "--stub") options.Stubs.Add(args[i + 1]);
            else if (args[i] == "--export") exportNames.Add(args[i + 1]);
            else if (args[i] == "--sprx") sprxExtras.Add(args[i + 1]);
            else if (args[i] == "--kernel-sprx") kernelSprx = args[i + 1];
        }
        if (objectPaths.Count == 0)
        {
            Console.Error.WriteLine("Usage: link --obj <file.o> [--obj ...] [--lib <archive.a> ...] [--stub <stub.o> ...]");
            Console.Error.WriteLine("       [--self-contained] supplies the start object and the core module stubs.");
            Console.Error.WriteLine("       [--export <name> ...] exports the named defined symbols (for a --kind prx library).");
            Console.Error.WriteLine("       [--publish-name <name>] the name the module publishes itself under (default: the output file name without its extension).");
            Console.Error.WriteLine("       [--export-library <name>] the library the exports are published under (default: the name above).");
            return 1;
        }

        string? kindArg = GetOption(args, "--kind");
        if (kindArg is not null
            && !string.Equals(kindArg, "eboot", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(kindArg, "prx", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(kindArg, "payload", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Unknown --kind: " + kindArg);
            return 1;
        }
        // A self-contained link supplies its own start object and compat layer, and the two executable
        // classes (eboot vs payload) get different compat objects. Omitting --kind would silently
        // default to eboot, which gives the wrong compat body to a payload and the wrong per-thread
        // storage to an eboot built as if it were a payload. Require the choice to be explicit so the
        // build fails here rather than at run time on the device.
        if (kindArg is null && HasFlag(args, "--self-contained"))
        {
            Console.Error.WriteLine("A --self-contained link requires --kind (eboot, prx, or payload).");
            return 1;
        }
        bool payload = string.Equals(kindArg, "payload", StringComparison.OrdinalIgnoreCase);
        ModuleKind kind = string.Equals(kindArg, "prx", StringComparison.OrdinalIgnoreCase)
            ? ModuleKind.Library : ModuleKind.Executable;

        // A payload link wraps the runtime bootstrapper's own main so the shim's wrapper can trigger
        // the C library's lazy thread setup before the runtime asks for an allocation. The wrapping is
        // done here by renaming every input object's main symbol to __prospero_bootstrapper_main; the
        // shim declares main itself and calls the renamed one. Any object without a main symbol is left
        // as-is.
        if (payload)
        {
            foreach (string path in objectPaths)
                options.ExtraObjects.Add(LoadPayloadObject(path));
        }
        else
        {
            foreach (string path in objectPaths)
                options.Objects.Add(path);
        }

        // The self-contained link supplies its own start object and its own stubs for the modules the
        // SDK imports from, so a build needs no start file or stub library from elsewhere. A library
        // module has no program entry, so it takes the stubs but not the start object.
        if (HasFlag(args, "--self-contained"))
        {
            if (payload)
            {
                // A payload starts through its own resolver-driven start object and imports no modules;
                // every outside reference is resolved at run time, so it needs no stub libraries. The
                // start object is fully self-contained: bss zero, constructor walk, main call, result
                // relay to the loader's output slot, plain ret. No embedded prebuilt runtime.
                if (HasFlag(args, "--diagnostics"))
                    PayloadCrtEmitter.EmitDiagnosticBreadcrumbs = true;
                if (HasFlag(args, "--return-on-exit"))
                    PayloadCrtEmitter.ReturnOnExit = true;
                options.ExtraObjects.Add(ElfObjectReader.Read(PayloadCrtEmitter.BuildStartObject(), "sharpprospero_payload_crt.o"));
            }
            else if (kind == ModuleKind.Executable)
                options.ExtraObjects.Add(ElfObjectReader.Read(CrtEmitter.BuildStartObject(), "sharpprospero_crt.o"));
            // The compat object defines the C-library names the ahead-of-time runtime imports that the
            // device modules do not publish. It is needed only when the runtime archives are linked, so
            // a bare link (no runtime) does not carry it.
            if (options.Archives.Count > 0)
                options.ExtraObjects.Add(ElfObjectReader.Read(CompatEmitter.BuildObject(payload ? ModuleKind.Executable : kind, payload), "sharpprospero_compat.o"));
            if (!payload)
                foreach (StubCatalog.Entry entry in StubCatalog.Core)
                    options.ExtraStubs.Add(StubLibrary.Parse(
                        PrxStubEmitter.BuildObject(entry.Library, entry.Exports, entry.ModuleVersion, entry.LibraryVersion, entry.ModuleName, entry.Soname),
                        entry.Library + ".prx"));
        }

        try
        {
            LinkResolution result = Linker.Resolve(options);
            Console.WriteLine($"Included objects: {result.Included.Count}");
            Console.WriteLine($"Defined symbols:  {result.Defined.Count}");
            Console.WriteLine($"Imports:          {result.Imports.Count}");
            foreach (ImportSymbol imp in result.Imports)
                Console.WriteLine($"  -> {imp.Name}  ({imp.ModuleName})");
            Console.WriteLine($"Unresolved:       {result.Unresolved.Count}");
            foreach (string name in result.Unresolved)
                Console.WriteLine($"  ? {name}");
            if (result.SkippedMembers.Count > 0)
            {
                Console.WriteLine($"Skipped members:  {result.SkippedMembers.Count}");
                foreach (string skip in result.SkippedMembers)
                    Console.WriteLine($"  ! {skip}");
            }

            string? outPath = GetOption(args, "--out");
            if (outPath is not null)
            {
                // A payload has no dynamic linker; its outside references resolve at run time, so an
                // unresolved reference is expected. An application or library must resolve everything.
                if (!payload && result.Unresolved.Count > 0)
                {
                    Console.Error.WriteLine($"{result.Unresolved.Count} symbol(s) are unresolved; nothing written.");
                    return 2;
                }
                string full = Path.GetFullPath(outPath);
                byte[] module;
                if (payload)
                {
                    // A payload starts at its resolver-driven start object; its outside references become
                    // run-time-resolved names rather than module imports. The DT_NEEDED SPRX list is
                    // built from the sample-declared --sprx items (in order) merged with the canonical
                    // default set; --kernel-sprx overrides the default kernel module when the sample
                    // needs libkernel_sys or another kernel SPRX. Extraction happens above; here we
                    // compose the final list so PayloadWriter emits the correct DT_NEEDED entries.
                    string entry = GetOption(args, "--entry") ?? PayloadCrtEmitter.StartSymbol;
                    string[]? neededSprx = (sprxExtras.Count > 0 || kernelSprx is not null)
                        ? PayloadProfile.BuildNeededSprx(sprxExtras.ToArray(), kernelSprx)
                        : null;
                    module = PayloadWriter.Write(result, entry, neededSprx);
                }
                else
                {
                    // A self-contained executable starts at the injected start object's entry, not at
                    // main; defaulting to main would set e_entry past the start object and skip the stack
                    // alignment and the exit call it performs.
                    string defaultEntry = HasFlag(args, "--self-contained") && kind == ModuleKind.Executable
                        ? CrtEmitter.StartSymbol : "main";
                    string entry = GetOption(args, "--entry") ?? defaultEntry;
                    module = DynamicWriter.Write(result, entry, kind,
                        exportNames.Count > 0 ? exportNames : null, Path.GetFileName(full),
                        GetOption(args, "--publish-name"), GetOption(args, "--export-library"));
                }
                File.WriteAllBytes(full, module);
                Console.WriteLine($"Wrote {full} ({module.Length} bytes"
                    + (exportNames.Count > 0 ? $", {exportNames.Count} export(s)" : "") + ").");
            }
            return 0;
        }
        catch (Exception ex) when (ex is ElfLinkException or IOException)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
    }

    // Generates kernel module ELF blobs (kelf + uelf) as a C# source file with static
    // ReadOnlySpan<byte> arrays. Runs at build time, matching the C reference Makefile which
    // compiles the kernel module from C source before linking the loader.
    private static int RunKmod(string[] args)
    {
        string outPath = "";
        string ns = "SampleApp";
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--out" && i + 1 < args.Length) outPath = args[++i];
            else if (args[i] == "--namespace" && i + 1 < args.Length) ns = args[++i];
        }
        if (string.IsNullOrEmpty(outPath))
        {
            Console.Error.WriteLine("kmod: --out <file.cs> required");
            return 1;
        }

        var output = KernelModuleWriter.Build();
        byte[] kelf = output.KelfElf ?? [];
        byte[] uelf = output.UelfElf ?? [];
        Console.Error.WriteLine($"kmod: kelf {kelf.Length} bytes, uelf {uelf.Length} bytes");

        var sb = new StringBuilder();
        sb.AppendLine("// Auto-generated at build time. Do not edit.");
        sb.AppendLine($"using System;");
        sb.AppendLine();
        sb.AppendLine($"namespace {ns};");
        sb.AppendLine();
        sb.AppendLine("internal static class KernelModuleBlobs");
        sb.AppendLine("{");
        sb.Append("    internal static ReadOnlySpan<byte> Kelf => [");
        FormatBlobBytes(sb, kelf);
        sb.AppendLine("];");
        sb.AppendLine();
        sb.Append("    internal static ReadOnlySpan<byte> Uelf => [");
        FormatBlobBytes(sb, uelf);
        sb.AppendLine("];");
        sb.AppendLine("}");

        Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
        File.WriteAllText(outPath, sb.ToString(), new UTF8Encoding(false));
        Console.Error.WriteLine($"kmod: wrote {outPath}");
        return 0;
    }

    private static void FormatBlobBytes(StringBuilder sb, byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            if (i > 0) sb.Append(',');
            if (i % 32 == 0) { sb.AppendLine(); sb.Append("        "); }
            sb.Append($"0x{data[i]:X2}");
        }
        if (data.Length > 0) { sb.AppendLine(); sb.Append("    "); }
    }

    // Compares the export surfaces of two modules: which identifiers one has and the other does not, and
    // which are present in both but at a different address. Useful for seeing what changed between two
    // firmware builds of the same module.
    private static int RunDiff(string[] args)
    {
        string? a = GetOption(args, "--a");
        string? b = GetOption(args, "--b");
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b) || !File.Exists(a) || !File.Exists(b))
        {
            Console.Error.WriteLine("Usage: diff --a <module> --b <module>");
            Console.Error.WriteLine("  Reports the export identifiers added, removed, and moved from A to B.");
            return 1;
        }
        try
        {
            PrxImage imageA = PrxImage.Parse(ModuleFile.Read(a).Elf);
            PrxImage imageB = PrxImage.Parse(ModuleFile.Read(b).Elf);
            var mapA = new Dictionary<string, PrxExport>(StringComparer.Ordinal);
            foreach (PrxExport e in imageA.Exports) mapA[e.Nid] = e;
            var mapB = new Dictionary<string, PrxExport>(StringComparer.Ordinal);
            foreach (PrxExport e in imageB.Exports) mapB[e.Nid] = e;

            var removed = new List<string>();
            var moved = new List<string>();
            foreach (KeyValuePair<string, PrxExport> kv in mapA)
            {
                if (!mapB.TryGetValue(kv.Key, out PrxExport other))
                    removed.Add(Label(kv.Value));
                else if (other.Value != kv.Value.Value)
                    moved.Add($"{Label(kv.Value)}  0x{kv.Value.Value:x} -> 0x{other.Value:x}");
            }
            var added = new List<string>();
            foreach (KeyValuePair<string, PrxExport> kv in mapB)
                if (!mapA.ContainsKey(kv.Key))
                    added.Add(Label(kv.Value));
            removed.Sort(StringComparer.Ordinal);
            added.Sort(StringComparer.Ordinal);
            moved.Sort(StringComparer.Ordinal);

            Console.WriteLine($"A: {Path.GetFileName(a)} ({imageA.Exports.Count} exports)");
            Console.WriteLine($"B: {Path.GetFileName(b)} ({imageB.Exports.Count} exports)");
            Console.WriteLine($"Removed (in A, not B): {removed.Count}");
            foreach (string s in removed) Console.WriteLine($"  - {s}");
            Console.WriteLine($"Added (in B, not A): {added.Count}");
            foreach (string s in added) Console.WriteLine($"  + {s}");
            Console.WriteLine($"Moved (same identifier, different address): {moved.Count}");
            foreach (string s in moved) Console.WriteLine($"  ~ {s}");
            return removed.Count > 0 || added.Count > 0 ? 1 : 0;
        }
        catch (Exception ex) when (ex is PrxFormatException or IOException)
        {
            Console.Error.WriteLine($"Could not read a module: {ex.Message}");
            return 2;
        }

        static string Label(PrxExport e)
            => string.IsNullOrEmpty(e.LibraryName) ? e.Nid : $"{e.Nid} [{e.LibraryName}]";
    }

    // Converts between WAV and VAG, choosing the direction from the input's contents: a WAV becomes a
    // VAG, a VAG becomes a WAV.
    private static int RunVag(string[] args)
    {
        string? input = GetOption(args, "--input") ?? GetOption(args, "-i");
        string? output = GetOption(args, "--output") ?? GetOption(args, "-o");
        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(output))
        {
            Console.Error.WriteLine("Usage: vag --input <clip.wav|clip.vag> --output <clip.vag|clip.wav> [--name <name>]");
            Console.Error.WriteLine("  Converts a 16-bit PCM WAV to VAG, or a VAG back to WAV.");
            return 1;
        }
        if (!File.Exists(input))
        {
            Console.Error.WriteLine($"Input not found: {input}");
            return 1;
        }
        try
        {
            byte[] bytes = File.ReadAllBytes(input);
            bool isVag = bytes.Length >= 4 && bytes[0] == 'V' && bytes[1] == 'A' && bytes[2] == 'G' && bytes[3] == 'p';
            byte[] result;
            string what;
            if (isVag)
            {
                SharpProspero.Audio.PcmAudio pcm = SharpProspero.Audio.VagAudio.Decode(bytes);
                result = SharpProspero.Audio.WavAudio.Encode(pcm);
                what = $"WAV ({pcm.Channels} ch, {pcm.SampleRate} Hz, {pcm.FrameCount} frames)";
            }
            else
            {
                SharpProspero.Audio.PcmAudio pcm = SharpProspero.Audio.WavAudio.Decode(bytes);
                result = SharpProspero.Audio.VagAudio.Encode(pcm, GetOption(args, "--name") ?? "");
                what = $"VAG ({pcm.Channels} ch, {pcm.SampleRate} Hz)";
            }
            File.WriteAllBytes(output, result);
            Console.WriteLine($"Wrote {output} - {what}, {result.Length} bytes.");
            return 0;
        }
        catch (SharpProspero.Interop.ProsperoException ex)
        {
            Console.Error.WriteLine($"Cannot convert: {ex.Message}");
            return 2;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine(ex.Message);
            return 3;
        }
    }

    // Reports a compiled shader binary: its kind, version, sizes and the register writes it carries,
    // and with --registers the full register lists.
    private static int RunShader(string[] args)
    {
        string? file = GetOption(args, "--file") ?? GetOption(args, "--input") ?? GetOption(args, "-i");
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
        {
            Console.Error.WriteLine("Usage: shader --file <shader.sb> [--registers]");
            return 1;
        }
        try
        {
            ShaderInfo info = ShaderInfo.Read(File.ReadAllBytes(file));
            Console.WriteLine($"File:     {Path.GetFileName(file)}");
            Console.WriteLine($"Valid:    {(info.IsValid ? "yes" : "no (unexpected header magic)")}");
            Console.WriteLine($"Kind:     {info.KindName} (0x{info.Kind:X2})");
            Console.WriteLine($"Version:  {info.Version}");
            Console.WriteLine($"Header:   {info.DeclaredHeaderSize} bytes");
            Console.WriteLine($"Code:     {info.CodeSectionSize} bytes ({info.DeclaredCodeSize} declared)");
            Console.WriteLine($"Context registers: {info.ContextRegisters.Count}");
            Console.WriteLine($"Shader registers:  {info.ShaderRegisters.Count}");
            if (HasFlag(args, "--registers"))
            {
                PrintShaderRegisters("Context registers", info.ContextRegisters);
                PrintShaderRegisters("Shader registers", info.ShaderRegisters);
            }
            return info.IsValid ? 0 : 2;
        }
        catch (PrxFormatException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            return 3;
        }
    }

    private static void PrintShaderRegisters(string title, IReadOnlyList<ShaderRegisterWrite> registers)
    {
        if (registers.Count == 0)
            return;
        Console.WriteLine($"{title}:");
        foreach (ShaderRegisterWrite reg in registers)
            Console.WriteLine($"  0x{reg.Offset:X4} = 0x{reg.Value:X8}");
    }

    // Parses a "WxH" size string into two positive dimensions.
    private static bool TryParseSize(string text, out int width, out int height)
    {
        width = height = 0;
        int x = text.IndexOfAny(['x', 'X', '*']);
        if (x <= 0 || x == text.Length - 1)
            return false;
        return int.TryParse(text[..x], NumberStyles.Integer, CultureInfo.InvariantCulture, out width) && width > 0
            && int.TryParse(text[(x + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out height) && height > 0;
    }

    // Prints the header, program headers, dependencies and, with --exports, the exported symbols of an
    // ELF module, without an external tool.
    // Builds a GNF texture from a PNG, TGA, or BMP image, or reports a GNF's header with --info.
    private static int RunGnf(string[] args)
    {
        string? info = GetOption(args, "--info");
        if (!string.IsNullOrEmpty(info))
        {
            if (!File.Exists(info))
            {
                Console.Error.WriteLine($"File not found: {info}");
                return 1;
            }
            try
            {
                GnfInfo gnf = GnfReader.Read(File.ReadAllBytes(info));
                Console.WriteLine($"File:      {Path.GetFileName(info)}");
                Console.WriteLine($"Version:   {gnf.Version}");
                Console.WriteLine($"Textures:  {gnf.TextureCount}");
                Console.WriteLine($"Alignment: {gnf.Alignment} bytes");
                Console.WriteLine($"Size:      {gnf.StreamSize} bytes");
                Console.WriteLine($"Texture 0: {gnf.Width}x{gnf.Height}, format 0x{gnf.DataFormat:X2}, "
                    + $"tiling {(gnf.TileMode == 0 ? "linear" : gnf.TileMode.ToString(CultureInfo.InvariantCulture))}, "
                    + $"{gnf.PixelSize} pixel bytes");
                return 0;
            }
            catch (Exception ex) when (ex is ImageFormatException or IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine(ex.Message);
                return 2;
            }
        }

        string? input = GetOption(args, "--input") ?? GetOption(args, "-i");
        string? output = GetOption(args, "--output") ?? GetOption(args, "-o");
        bool srgb = HasFlag(args, "--srgb");
        string? resize = GetOption(args, "--resize");
        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(output))
        {
            Console.Error.WriteLine("Usage: gnf --input <image.png|.tga|.bmp> --output <file.gnf> [--srgb] [--resize WxH]");
            Console.Error.WriteLine("       gnf --info <file.gnf>");
            return 1;
        }
        if (!File.Exists(input))
        {
            Console.Error.WriteLine($"Input image not found: {input}");
            return 1;
        }
        if (resize is not null && !TryParseSize(resize, out _, out _))
        {
            Console.Error.WriteLine("--resize takes a size like 256x256.");
            return 1;
        }
        try
        {
            DecodedImage image = DecodedImage.Load(input);
            if (resize is not null && TryParseSize(resize, out int rw, out int rh))
                image = ImageOps.Resize(image, rw, rh);
            byte[] gnf = GnfWriter.Build(image, srgb);
            File.WriteAllBytes(output, gnf);
            Console.WriteLine($"Wrote {output}");
            Console.WriteLine($"  {image.Width}x{image.Height}, four 8-bit channels, linear, {gnf.Length} bytes");
            return 0;
        }
        catch (ImageFormatException ex)
        {
            Console.Error.WriteLine($"Cannot read image: {ex.Message}");
            return 2;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
    }

    // Sends a built payload to a listening loader over the network. The loader reads the whole ELF from
    // the connection and runs it in place.
    private static int RunPayload(string[] args)
    {
        string? file = GetOption(args, "--file");
        string? host = GetOption(args, "--host");
        if (!HasFlag(args, "--send") || string.IsNullOrEmpty(file) || string.IsNullOrEmpty(host))
        {
            Console.Error.WriteLine("Usage: payload --send --host <address> [--port 9021] --file <payload.elf>");
            return 1;
        }
        if (!File.Exists(file))
        {
            Console.Error.WriteLine($"Payload not found: {file}");
            return 1;
        }
        string? portText = GetOption(args, "--port");
        int port = 9021;
        if (portText is not null && (!int.TryParse(portText, NumberStyles.Integer, CultureInfo.InvariantCulture, out port) || port is < 1 or > 65535))
        {
            Console.Error.WriteLine("--port takes a number from 1 to 65535.");
            return 1;
        }
        try
        {
            byte[] bytes = File.ReadAllBytes(file);
            using var client = new System.Net.Sockets.TcpClient();
            client.Connect(host, port);
            using System.Net.Sockets.NetworkStream stream = client.GetStream();
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();
            Console.WriteLine($"Sent {bytes.Length} bytes to {host}:{port}.");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException)
        {
            Console.Error.WriteLine($"Could not send the payload: {ex.Message}");
            return 2;
        }
    }

    /// <summary>
    /// Checks that every module the application has to carry travels with it, and copies in the ones
    /// that are missing when a source folder is given. Returns a failure when one cannot be found, so
    /// a build stops rather than producing a package that hangs a console at launch.
    /// </summary>
    private static int RunModules(string[] args)
    {
        string? module = GetOption(args, "--module");
        string? folder = GetOption(args, "--folder");
        string? source = GetOption(args, "--source");
        if (string.IsNullOrEmpty(module) || !File.Exists(module))
        {
            Console.Error.WriteLine("Usage: modules --module <eboot.bin> --folder <sce_module folder> [--source <folder>]");
            Console.Error.WriteLine("  Reports the modules the application has to carry, gathers any missing from --source,");
            Console.Error.WriteLine("  and fails when one is neither present nor available.");
            return 1;
        }

        IReadOnlyList<string> needed;
        try
        {
            needed = PrxImage.Parse(ModuleFile.Read(module).Elf).NeededModules;
        }
        catch (Exception ex) when (ex is PrxFormatException or IOException)
        {
            Console.Error.WriteLine($"Could not read {Path.GetFileName(module)}: {ex.Message}");
            return 1;
        }

        IReadOnlyList<string> required = BundledModules.Required(needed);
        if (required.Count == 0)
        {
            Console.WriteLine("  No module has to travel with this application.");
            return 0;
        }

        var missing = new List<string>();
        foreach (string name in required)
        {
            string destination = Path.Combine(folder ?? ".", name);
            if (File.Exists(destination))
            {
                Console.WriteLine($"  {name}: present");
                continue;
            }
            string? candidate = string.IsNullOrEmpty(source) ? null : Path.Combine(source, name);
            if (candidate is not null && File.Exists(candidate))
            {
                Directory.CreateDirectory(folder ?? ".");
                File.Copy(candidate, destination, overwrite: true);
                Console.WriteLine($"  {name}: gathered");
                continue;
            }
            Console.WriteLine($"  {name}: MISSING");
            missing.Add(name);
        }

        if (missing.Count == 0)
            return 0;

        Console.Error.WriteLine();
        Console.Error.WriteLine($"This application names {missing.Count} module(s) that it has to carry with it, and they are not present:");
        foreach (string name in missing)
            Console.Error.WriteLine($"  {name}");
        Console.Error.WriteLine();
        Console.Error.WriteLine("The system does not publish these; an application supplies its own copy. One that names a");
        Console.Error.WriteLine("module it does not carry installs cleanly and then hangs the console when launched, with");
        Console.Error.WriteLine("nothing written to the log, because the loader is resolving it before any of the");
        Console.Error.WriteLine("application's code runs.");
        Console.Error.WriteLine();
        Console.Error.WriteLine("Put a copy in the project's sce_module folder, or point ProsperoModuleFolder (or the");
        Console.Error.WriteLine("PROSPERO_MODULES environment variable) at a folder that has one.");
        return 2;
    }

    private static int RunElf(string[] args)
    {
        string? file = GetOption(args, "--file");
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
        {
            Console.Error.WriteLine("Usage: elf --file <module> [--exports]");
            Console.Error.WriteLine("       elf --file <module> --sizes            loadable size by kind");
            Console.Error.WriteLine("       elf --file <module> --symbols          the dynamic symbol table");
            Console.Error.WriteLine("       elf --file <module> --strings [--min N] printable strings (N defaults to 4)");
            Console.Error.WriteLine("       elf --file <module> --strip --out <file> a smaller module without section headers");
            return 1;
        }
        try
        {
            // Reads the file once and classifies it: a signed container is unwrapped to its embedded
            // ELF, so a .self or .sprx reports the same fields as a .elf or .prx.
            ModuleFile mf = ModuleFile.Read(file);
            if (HasFlag(args, "--sizes")) return ElfSizes(mf.Elf);
            if (HasFlag(args, "--symbols")) return ElfSymbols(mf.Elf);
            if (HasFlag(args, "--strings")) return ElfStrings(mf.Elf, args);
            if (HasFlag(args, "--strip")) return ElfStrip(mf.Elf, args);
            ElfInfo info = ElfInfo.Parse(mf.Elf);
            Console.WriteLine($"File:      {Path.GetFileName(file)}");
            Console.WriteLine($"Container: {(mf.IsSigned ? "signed (.self / .sprx)" : "unsigned ELF (.elf / .prx)")}");
            Console.WriteLine($"Class:     {(info.Is64Bit ? "ELF64" : "ELF32")}");
            Console.WriteLine($"OS/ABI:    {info.OsAbi}");
            Console.WriteLine($"Type:      {info.TypeName}");
            Console.WriteLine($"Machine:   0x{info.Machine:X2}{(info.Machine == 0x3E ? " (x86-64)" : "")}");
            Console.WriteLine($"Entry:     0x{info.Entry:X}");

            Console.WriteLine($"Program headers ({info.ProgramHeaders.Count}):");
            Console.WriteLine("  Type            Flags  VirtAddr           FileSize   MemSize");
            foreach (ElfProgramHeader ph in info.ProgramHeaders)
                Console.WriteLine($"  {ph.TypeName,-15} {ph.FlagsText}    0x{ph.VirtualAddress:X12}     0x{ph.FileSize:X8} 0x{ph.MemorySize:X8}");

            // Dynamic-module details when the file carries them; a plain object or executable does not.
            try
            {
                PrxImage image = PrxImage.Parse(mf.Elf);
                if (image.SdkVersion != 0)
                {
                    Console.WriteLine($"Built for: {image.RequiredSystemVersion} "
                        + $"(0x{image.SdkVersion:X8}) - a package shipping this module must require at least this.");
                }
                if (image.NeededModules.Count > 0)
                {
                    Console.WriteLine($"Needed modules ({image.NeededModules.Count}):");
                    foreach (string module in image.NeededModules)
                        Console.WriteLine($"  {module}");
                }
                Console.WriteLine($"Exports: {image.Exports.Count}");
                if (HasFlag(args, "--exports"))
                {
                    foreach (PrxExport export in image.Exports)
                        Console.WriteLine($"  {export.Nid}  lib={export.LibraryId} mod={export.ModuleId} {(export.IsFunction ? "func" : "data")} {export.LibraryName}");
                }
            }
            catch (PrxFormatException)
            {
                // Not a dynamic module (no dynamic segment); the header and program headers stand alone.
            }
            return 0;
        }
        catch (Exception ex) when (ex is PrxFormatException or IOException)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
    }

    // The loadable footprint of a module, split by segment kind.
    private static int ElfSizes(byte[] elf)
    {
        ElfSegmentSizes s = ElfTools.SegmentSizes(elf);
        Console.WriteLine("Loadable size:");
        Console.WriteLine($"  code       {s.Code,12:N0} bytes");
        Console.WriteLine($"  read-only  {s.ReadOnly,12:N0} bytes");
        Console.WriteLine($"  data       {s.Data,12:N0} bytes");
        Console.WriteLine($"  zero-fill  {s.Bss,12:N0} bytes");
        Console.WriteLine($"  file       {s.File,12:N0} bytes");
        Console.WriteLine($"  memory     {s.Memory,12:N0} bytes");
        return 0;
    }

    // The module's dynamic symbol table, defined entries and imports alike.
    private static int ElfSymbols(byte[] elf)
    {
        IReadOnlyList<ElfSymbolEntry> symbols = ElfTools.DynamicSymbols(elf);
        if (symbols.Count == 0)
        {
            Console.WriteLine("No dynamic symbol table (the module has no dynamic segment).");
            return 0;
        }
        Console.WriteLine($"Dynamic symbols ({symbols.Count}):");
        Console.WriteLine("  Value          Size  Type     Bind    Where     Name");
        foreach (ElfSymbolEntry sym in symbols)
        {
            if (sym.Name.Length == 0 && sym.Value == 0 && sym.Size == 0)
                continue; // the leading null entry
            Console.WriteLine($"  0x{sym.Value:X12} {sym.Size,6}  {sym.TypeName,-7}  {sym.BindName,-6}  {(sym.IsImport ? "import" : "defined"),-8}  {sym.Name}");
        }
        return 0;
    }

    // The printable strings in the module, each with the offset it starts at.
    private static int ElfStrings(byte[] elf, string[] args)
    {
        int min = int.TryParse(GetOption(args, "--min"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int m) && m > 0 ? m : 4;
        foreach ((long offset, string text) in ElfTools.Strings(elf, min))
            Console.WriteLine($"0x{offset:X8}  {text}");
        return 0;
    }

    // Writes a smaller copy of the module without its section headers, which a dynamic loader does not read.
    private static int ElfStrip(byte[] elf, string[] args)
    {
        string? outPath = GetOption(args, "--out");
        if (string.IsNullOrEmpty(outPath))
        {
            Console.Error.WriteLine("Pass --out <file> for --strip.");
            return 1;
        }
        try
        {
            byte[] stripped = ElfTools.Strip(elf);
            string full = Path.GetFullPath(outPath);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllBytes(full, stripped);
            Console.WriteLine($"Wrote {full} ({stripped.Length:N0} bytes, was {elf.Length:N0}; removed {elf.Length - stripped.Length:N0} bytes).");
            return 0;
        }
        catch (PrxFormatException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            return 3;
        }
    }

    // Converts between the two forms and reports which a file is. Without an action it inspects;
    // --sign wraps an ELF in a signed container a development console accepts; --extract recovers the
    // ELF from a signed container.
    private static int RunSelf(string[] args)
    {
        string? file = GetOption(args, "--file") ?? GetOption(args, "--in");
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
        {
            Console.Error.WriteLine("Usage: self --inspect --file <file>");
            Console.Error.WriteLine("       self --sign --in <file.elf|.prx> --out <file.self|.sprx> [--app-version 0xNN --fw-version 0xNN --authority 0xNN]");
            Console.Error.WriteLine("       self --extract --in <file.self|.sprx> --out <file.elf|.prx>");
            return 1;
        }

        byte[] data;
        try { data = File.ReadAllBytes(file); }
        catch (IOException ex) { Console.Error.WriteLine($"Cannot read {file}: {ex.Message}"); return 3; }

        bool sign = HasFlag(args, "--sign");
        bool extract = HasFlag(args, "--extract");
        if (!sign && !extract)
            return InspectSelf(file, data);

        string? outPath = GetOption(args, "--out");
        if (string.IsNullOrEmpty(outPath))
        {
            Console.Error.WriteLine("Pass --out <file> for --sign and --extract.");
            return 1;
        }
        string full = Path.GetFullPath(outPath);

        try
        {
            byte[] result;
            string kind;
            if (sign)
            {
                // Wrapping a module that is already wrapped would nest one container inside another and
                // produce a file nothing can load. Report it and leave the input as it is, so running
                // the step twice - or over a folder that mixes built and supplied modules - is safe.
                // Both header marks count as wrapped: modules carrying the second one are shipped by
                // titles that run, and unwrapping and wrapping such a module again would replace a
                // container that works with one this toolchain happens to write.
                if (SelfContainer.IsSelf(data))
                {
                    Console.WriteLine($"{file} is already wrapped; left unchanged.");
                    return 0;
                }

                // A version or authority given but not a valid hex number is a mistake (a dotted "9.00",
                // say); reject it rather than signing with a silently defaulted zero.
                if (!ValidHexOrAbsent(args, "--app-version", out ulong appVersion)
                    || !ValidHexOrAbsent(args, "--fw-version", out ulong firmwareVersion)
                    || !ValidHexOrAbsent(args, "--authority", out ulong authority))
                {
                    Console.Error.WriteLine("--app-version, --fw-version and --authority take a hex value like 0x02000000.");
                    return 1;
                }
                var options = new SelfSignOptions
                {
                    AppVersion = appVersion,
                    FirmwareVersion = firmwareVersion,
                    AuthorityId = GetOption(args, "--authority") is not null ? authority : null,
                    NormalizeHeader = !HasFlag(args, "--no-normalize"),
                };
                result = SelfContainer.Sign(data, options);
                kind = "signed container";
            }
            else
            {
                result = SelfContainer.ExtractElf(data);
                kind = "unsigned ELF";
            }
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllBytes(full, result);
            Console.WriteLine($"Wrote {full} ({result.Length} bytes, {kind}).");
            return 0;
        }
        catch (PrxFormatException ex) { Console.Error.WriteLine(ex.Message); return 2; }
        catch (IOException ex) { Console.Error.WriteLine(ex.Message); return 3; }
    }

    // Reports which of the forms a file is, and the little it can read of each.
    private static int InspectSelf(string file, byte[] data)
    {
        Console.WriteLine($"File:      {Path.GetFileName(file)}");
        switch (SelfContainer.Classify(data))
        {
            case ModuleForm.SignedPlaintext:
                SelfImage image;
                try { image = SelfContainer.Parse(data); }
                catch (PrxFormatException ex) { Console.Error.WriteLine(ex.Message); return 2; }

                Console.WriteLine("Container: signed (.self / .sprx), readable");
                Console.WriteLine($"Segments:  {image.Segments.Count}");
                foreach (SelfSegment seg in image.Segments)
                {
                    var attrs = new List<string>();
                    if (seg.Blocked) attrs.Add("payload");
                    if (seg.Compressed) attrs.Add("compressed");
                    if (seg.Encrypted) attrs.Add("encrypted");
                    if (seg.Signed) attrs.Add("signed");
                    Console.WriteLine($"  segment {seg.Id}: {seg.FileSize} bytes{(attrs.Count > 0 ? " (" + string.Join(", ", attrs) + ")" : "")}");
                }
                if (image.ExtInfo is SelfExtInfo ext)
                {
                    Console.WriteLine($"Authority: 0x{ext.AuthorityId:X16}");
                    Console.WriteLine($"Prog type: 0x{ext.ProgramType:X16}");
                    Console.WriteLine($"App ver:   0x{ext.AppVersion:X16}");
                    Console.WriteLine($"Fw ver:    0x{ext.FirmwareVersion:X16}");
                    Console.WriteLine($"Digest:    {Convert.ToHexString(ext.Digest)}");
                }
                try
                {
                    ElfInfo info = ElfInfo.Parse(SelfContainer.ExtractElf(data));
                    Console.WriteLine($"ELF type:  {info.TypeName}");
                    SelfIntegrity integrity = SelfContainer.CheckIntegrity(data);
                    // The digest covers the ELF that was wrapped, but a container stores only the
                    // segments it selects, so unwrapping is lossy for any module carrying content
                    // outside them. Recomputing then differs from the stored value even though the
                    // container is intact, which is the case for most modules - so a difference is
                    // reported as inconclusive rather than as damage.
                    Console.WriteLine($"Integrity: {(!integrity.HasDigest ? "no stored digest"
                        : integrity.Matches ? "ok (digest matches the embedded ELF)"
                        : "not reproducible (the module carries content outside the stored segments, so unwrapping cannot recover the exact ELF that was wrapped)")}");
                }
                catch (PrxFormatException) { }
                return 0;

            case ModuleForm.SignedEncrypted:
                Console.WriteLine("Container: signed and encrypted (.self / .sprx), for a retail console");
                Console.WriteLine("Data:      encrypted; its contents cannot be read without its key");
                return 0;

            case ModuleForm.UnsignedElf:
                Console.WriteLine("Container: unsigned ELF (.elf / .prx)");
                Console.WriteLine($"ELF type:  {ElfInfo.Parse(data).TypeName}");
                return 0;

            default:
                Console.Error.WriteLine("File is neither an ELF nor a signed container.");
                return 2;
        }
    }

    // Dumps a supplied module's export surface so a firmware's facts can be contributed. Reads any of
    // the four forms (a signed container is unwrapped first); --coverage reports how it covers the
    // names the SDK needs, and --text prints a human-readable form instead of JSON.
    private static int RunOffsets(string[] args)
    {
        string? file = GetOption(args, "--file") ?? GetOption(args, "--module");
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
        {
            Console.Error.WriteLine("Usage: offsets --file <module> [--firmware NN.NN] [--coverage] [--library <name>] [--text]");
            Console.Error.WriteLine("  Reads a .prx/.sprx/.elf/.self and dumps its export identifiers and addresses as JSON,");
            Console.Error.WriteLine("  so a firmware's facts can be contributed. --coverage matches the names the SDK needs");
            Console.Error.WriteLine("  and reports which are present; --library <name> targets one SDK catalog module.");
            Console.Error.WriteLine("  --text prints a human-readable form instead of JSON.");
            return 1;
        }

        byte[] data;
        try { data = File.ReadAllBytes(file); }
        catch (IOException ex) { Console.Error.WriteLine($"Cannot read {file}: {ex.Message}"); return 3; }

        string? firmware = GetOption(args, "--firmware");
        bool coverage = HasFlag(args, "--coverage");
        string? library = GetOption(args, "--library");

        OffsetReport report;
        try { report = OffsetReport.Create(Path.GetFileName(file), data, firmware, coverage, library); }
        catch (PrxFormatException ex) { Console.Error.WriteLine(ex.Message); return 2; }

        if (HasFlag(args, "--text"))
            Console.Write(report.ToText());
        else
            Console.WriteLine(OffsetsToJson(report));

        // A coverage run that found a name the SDK needs but the module does not export is the signal
        // worth a non-zero exit, so a contribution script can notice a firmware that moved a symbol.
        return report.Coverage is { Missing.Count: > 0 } ? 4 : 0;
    }

    private static string OffsetsToJson(OffsetReport report)
    {
        var root = new JsonObject
        {
            ["file"] = report.File,
            ["container"] = report.Container,
            ["firmware"] = report.Firmware,
            ["builtAgainst"] = report.BuiltAgainst,
            ["exportsReadable"] = report.ExportsReadable,
        };
        if (report.Note is not null)
            root["note"] = report.Note;

        if (report.ExportsReadable)
        {
            root["moduleName"] = report.ModuleName;
            root["libraryVersion"] = $"0x{report.LibraryVersion:X4}";

            var needed = new JsonArray();
            foreach (string module in report.NeededModules)
                needed.Add(module);
            root["neededModules"] = needed;

            var exports = new JsonArray();
            foreach (PrxExport export in report.Exports)
                exports.Add(new JsonObject
                {
                    ["nid"] = export.Nid,
                    ["library"] = export.LibraryName,
                    ["kind"] = export.IsFunction ? "func" : "data",
                    ["address"] = $"0x{export.Value:X}",
                });
            root["exports"] = exports;
        }

        if (report.Coverage is OffsetCoverage coverage)
        {
            var symbols = new JsonArray();
            foreach (OffsetSymbol symbol in coverage.Symbols)
            {
                var node = new JsonObject
                {
                    ["name"] = symbol.Name,
                    ["nid"] = symbol.Nid,
                    ["present"] = symbol.Present,
                };
                if (symbol.Present)
                {
                    node["kind"] = symbol.IsFunction ? "func" : "data";
                    node["address"] = $"0x{symbol.Address:X}";
                }
                symbols.Add(node);
            }

            var missing = new JsonArray();
            foreach (string name in coverage.Missing)
                missing.Add(name);

            root["coverage"] = new JsonObject
            {
                ["matchedLibrary"] = coverage.MatchedLibrary,
                ["required"] = coverage.RequiredCount,
                ["present"] = coverage.PresentCount,
                ["missing"] = missing,
                ["symbols"] = symbols,
            };
        }

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        return root.ToJsonString(options);
    }

    // Retargets a module to another system: rewrites the version it records it was built against (the
    // load-time gate) and, optionally, a needed library's recorded version. A signed module is unwrapped,
    // edited, and re-signed. With no action it reports what the module currently targets.
    private static int RunRetarget(string[] args)
    {
        string? file = GetOption(args, "--file") ?? GetOption(args, "--module");
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
        {
            Console.Error.WriteLine("Usage: retarget --file <module.prx|.sprx> [--to NN.NN] [--set-lib-version <name>=0xNNNN ...] [--out <file>]");
            Console.Error.WriteLine("  With no action it reports the version the module targets and its library version tags.");
            Console.Error.WriteLine("  --to rewrites the version the module records it was built against (the load-time gate), so a");
            Console.Error.WriteLine("  module built for a newer system can load on an older one. --set-lib-version rewrites a needed");
            Console.Error.WriteLine("  library's recorded version. A signed module is unwrapped, edited, and re-signed.");
            return 1;
        }

        byte[] data;
        try { data = File.ReadAllBytes(file); }
        catch (IOException ex) { Console.Error.WriteLine($"Cannot read {file}: {ex.Message}"); return 3; }

        ModuleForm form = SelfContainer.Classify(data);
        if (form == ModuleForm.SignedEncrypted)
        {
            Console.Error.WriteLine("This is a signed and encrypted module; its contents cannot be read or edited without its key.");
            return 2;
        }
        if (form == ModuleForm.Unknown)
        {
            Console.Error.WriteLine("File is neither an ELF nor a signed container.");
            return 2;
        }

        bool signed = form == ModuleForm.SignedPlaintext;
        byte[] elf;
        try { elf = signed ? SelfContainer.ExtractElf(data) : (byte[])data.Clone(); }
        catch (PrxFormatException ex) { Console.Error.WriteLine(ex.Message); return 2; }

        string? toText = GetOption(args, "--to");
        var libVersions = new List<(string Name, ushort Version)>();
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (!string.Equals(args[i], "--set-lib-version", StringComparison.Ordinal))
                continue;
            string spec = args[i + 1];
            int eq = spec.IndexOf('=');
            if (eq <= 0 || !TryParseHexUShort(spec[(eq + 1)..], out ushort v))
            {
                Console.Error.WriteLine($"--set-lib-version expects <name>=0xNNNN, got '{spec}'.");
                return 1;
            }
            libVersions.Add((spec[..eq], v));
        }

        ModuleTargetInfo before;
        try { before = ModuleEditor.Read(elf); }
        catch (PrxFormatException ex) { Console.Error.WriteLine(ex.Message); return 2; }

        bool editing = toText is not null || libVersions.Count > 0;
        if (!editing)
        {
            Console.WriteLine($"File:       {Path.GetFileName(file)}");
            Console.WriteLine($"Container:  {(signed ? "signed (.self / .sprx)" : "unsigned ELF (.elf / .prx)")}");
            Console.WriteLine($"Targets:    {(before.SdkVersion == 0
                ? "no recorded version (loads on any system)"
                : $"{PrxImage.FormatSystemVersion(before.SdkVersion)} (0x{before.SdkVersion:X8})")}");
            foreach (LibraryTag tag in before.Libraries)
                Console.WriteLine($"  {tag.Kind,-15} {tag.Name,-28} v{(tag.Version >> 8) & 0xFF}.{tag.Version & 0xFF} (0x{tag.Version:X4})");
            return 0;
        }

        ushort? targetPacked = null;
        if (toText is not null)
        {
            if (!SystemVersion.TryParse(toText, out SystemVersion target))
            {
                Console.Error.WriteLine($"'{toText}' is not a system version. Use MM.mm, for example 09.00.");
                return 1;
            }
            targetPacked = target.Packed;
        }

        string? outPath = GetOption(args, "--out");
        if (string.IsNullOrEmpty(outPath))
        {
            Console.Error.WriteLine("Pass --out <file> to write the retargeted module.");
            return 1;
        }

        if (targetPacked is ushort packed)
        {
            if (!ModuleEditor.SetSdkVersion(elf, packed))
            {
                Console.WriteLine("The module records no version block, so it already loads on any system; version unchanged.");
            }
            else
            {
                ushort currentHigh = (ushort)(before.SdkVersion >> 16);
                string direction = packed < currentHigh ? "Downgraded" : packed > currentHigh ? "Upgraded" : "Set";
                Console.WriteLine($"{direction} target version to {PrxImage.FormatSystemVersion((uint)packed << 16)}.");
            }
        }

        foreach ((string name, ushort v) in libVersions)
        {
            int n = ModuleEditor.SetLibraryVersion(elf, name, v);
            Console.WriteLine(n > 0
                ? $"Set {name} version to 0x{v:X4} in {n} record(s)."
                : $"Warning: '{name}' is not a needed or imported library of this module; nothing changed.");
        }

        byte[] result = elf;
        string kind = "unsigned ELF";
        if (signed)
        {
            var options = new SelfSignOptions();
            try
            {
                SelfImage original = SelfContainer.Parse(data);
                if (original.ExtInfo is SelfExtInfo ext)
                    options = new SelfSignOptions { AuthorityId = ext.AuthorityId };
            }
            catch (PrxFormatException)
            {
                // Fall back to the default authority when the original header cannot be read.
            }
            try
            {
                result = SelfContainer.Sign(elf, options);
            }
            catch (PrxFormatException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 2;
            }
            kind = "signed container";
        }

        string full = Path.GetFullPath(outPath);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllBytes(full, result);
        }
        catch (IOException ex) { Console.Error.WriteLine(ex.Message); return 3; }
        Console.WriteLine($"Wrote {full} ({result.Length} bytes, {kind}).");
        return 0;
    }

    private static bool TryParseHexUShort(string text, out ushort value)
    {
        value = 0;
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ushort.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    // True when the option is absent (value stays zero) or present with a valid hex value; false only
    // when it is present but does not parse, so a malformed value is caught rather than silently zeroed.
    private static bool ValidHexOrAbsent(string[] args, string name, out ulong value)
    {
        value = 0;
        string? text = GetOption(args, name);
        if (string.IsNullOrEmpty(text))
            return true;
        return TryParseHexOption(args, name, out value);
    }

    private static bool TryParseHexOption(string[] args, string name, out ulong value)
    {
        value = 0;
        string? text = GetOption(args, name)?.Trim();
        if (string.IsNullOrEmpty(text))
            return false;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ulong.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    // Writes a link stub. The versions matter: an import records the module and library version, and a
    // module whose versions differ will not bind. Passing --module takes them from the module itself.
    private static int RunStub(string[] args)
    {
        string? library = GetOption(args, "--lib");
        string? namesPath = GetOption(args, "--names");
        string? outPath = GetOption(args, "--out");
        string? modulePath = GetOption(args, "--module");

        if (string.IsNullOrEmpty(namesPath) || string.IsNullOrEmpty(outPath) ||
            (string.IsNullOrEmpty(library) && string.IsNullOrEmpty(modulePath)))
        {
            Console.Error.WriteLine("Usage: stub --lib <libraryName> --names <file> --out <file.a>");
            Console.Error.WriteLine("       stub --module <file.prx> --names <file> --out <file.a>");
            Console.Error.WriteLine("  --module takes the library name, the module name and both versions from the");
            Console.Error.WriteLine("  module, so the stub matches what it publishes. --lib assumes the usual ones.");
            Console.Error.WriteLine("  --module-version / --library-version override either way.");
            Console.Error.WriteLine("  --module-name names the publishing module when it differs from the library.");
            Console.Error.WriteLine("  --soname names the file the loader loads when it is not <library>.prx.");
            return 1;
        }
        if (!File.Exists(namesPath))
        {
            Console.Error.WriteLine($"Names file not found: {namesPath}");
            return 1;
        }

        var names = new List<string>();
        foreach (string raw in File.ReadAllLines(namesPath))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;
            int split = line.IndexOfAny(['=', ':', '(']);
            names.Add(split < 0 ? line : line[..split].Trim());
        }

        ushort moduleVersion = PrxStubEmitter.DefaultModuleVersion;
        ushort libraryVersion = PrxStubEmitter.DefaultLibraryVersion;
        string? moduleName = GetOption(args, "--module-name");
        string? soname = GetOption(args, "--soname");

        if (!string.IsNullOrEmpty(modulePath))
        {
            if (!File.Exists(modulePath))
            {
                Console.Error.WriteLine($"Module not found: {modulePath}");
                return 1;
            }
            PrxImage image;
            try { image = PrxImage.Load(modulePath); }
            catch (Exception ex) when (ex is PrxFormatException or IOException)
            {
                Console.Error.WriteLine($"Cannot read module: {ex.Message}");
                return 2;
            }

            // The library the exports belong to and the module that publishes them are two different
            // names, and a module where they differ is common. Taking the module's own name as the
            // library asks the loader for a library nothing publishes.
            if (string.IsNullOrEmpty(library))
                library = image.ExportLibraryName.Length > 0
                    ? image.ExportLibraryName
                    : image.ModuleName.Length > 0
                        ? image.ModuleName
                        : Path.GetFileNameWithoutExtension(modulePath);
            moduleName ??= image.ModuleName.Length > 0 ? image.ModuleName : null;
            soname ??= Path.GetFileName(modulePath);
            libraryVersion = image.LibraryVersion;
            if (image.ModuleVersion != 0)
                moduleVersion = image.ModuleVersion;

            int missing = 0;
            foreach (string name in names)
            {
                if (image.FindByName(name) is null)
                {
                    Console.Error.WriteLine($"Warning: '{name}' is not exported by the module.");
                    missing++;
                }
            }
            Console.WriteLine($"Read {Path.GetFileName(modulePath)}: library '{library}', "
                + $"library version 0x{libraryVersion:X4}, {image.Exports.Count} export(s), {missing} name(s) not found.");
        }

        // A version given but unreadable is a mistake worth stopping for: taken as absent, the stub
        // is written with a version the module does not publish and the import it produces never binds.
        foreach ((string option, Action<ushort> set) in
                 ((string, Action<ushort>)[])[("--module-version", v => moduleVersion = v),
                                               ("--library-version", v => libraryVersion = v)])
        {
            string? text = GetOption(args, option);
            if (string.IsNullOrEmpty(text))
                continue;
            if (!TryParseHexUShort(text, out ushort value))
            {
                Console.Error.WriteLine($"{option} '{text}' is not a version. Write it in hexadecimal, for example 0x0101 or 0101.");
                return 1;
            }
            set(value);
        }

        string full = Path.GetFullPath(outPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        PrxStubEmitter.WriteStub(library!, names, full, moduleVersion, libraryVersion, moduleName, soname);
        Console.WriteLine($"Wrote {full} ({names.Count} exports, module version 0x{moduleVersion:X4}, "
            + $"library version 0x{libraryVersion:X4}, module '{moduleName ?? library}', "
            + $"file '{soname ?? library + ".prx"}').");
        return 0;
    }

    // Prints the identifier for one or more plain symbol names. A module keys its exports by this
    // identifier, so it is how a name is matched against a module that carries no plain names.
    private static int RunNid(string[] args)
    {
        var names = new List<string>();
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--name" && i + 1 < args.Length)
            {
                names.Add(args[i + 1]);
                i++;
            }
            else if (!args[i].StartsWith("--", StringComparison.Ordinal))
            {
                names.Add(args[i]);
            }
        }

        string? namesPath = GetOption(args, "--names");
        if (namesPath is not null && File.Exists(namesPath))
        {
            foreach (string raw in File.ReadAllLines(namesPath))
            {
                string line = raw.Trim();
                if (line.Length > 0 && !line.StartsWith('#'))
                    names.Add(line);
            }
        }

        if (names.Count == 0)
        {
            Console.Error.WriteLine("Usage: nid --name <symbol> [--name <symbol> ...] | nid --names <file>");
            return 1;
        }

        foreach (string name in names)
            Console.WriteLine($"{SceNid.Compute(name)}  {name}");
        return 0;
    }

    // Checks the metadata that describes the application to the system. A field carrying a value the
    // system does not recognise is reported as a fault and fails the command; a field a finished title
    // always carries but this one does not is reported as missing, and --apply fills it in.
    private static int RunParam(string[] args)
    {
        if (HasFlag(args, "--list"))
        {
            Console.WriteLine("Kinds of title:");
            foreach (ApplicationCategory known in ApplicationCategories.All)
                Console.WriteLine($"  {(int)known,-10} {known}");
            Console.WriteLine();
            Console.WriteLine($"An application that ships its own module uses {(int)ApplicationCategories.Default} ({ApplicationCategories.Default}).");
            return 0;
        }

        string? folder = GetOption(args, "--folder");
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            Console.Error.WriteLine("Usage: param --folder <module-folder> [--category <kind>] [--apply]");
            Console.Error.WriteLine("       param --list");
            return 1;
        }

        string paramPath = Path.Combine(folder, "sce_sys", "param.json");
        JsonObject? document = ReadParamJson(paramPath);
        if (document is null)
        {
            Console.Error.WriteLine(File.Exists(paramPath)
                ? $"{paramPath} is not readable as application metadata."
                : $"No application metadata found at {paramPath}.");
            return 1;
        }

        // A category given on the command line is applied before the check, so what is reported is the
        // metadata as it will be written rather than as it was found.
        string? categoryText = GetOption(args, "--category");
        if (categoryText is not null)
        {
            if (!ApplicationCategories.TryParse(categoryText, out ApplicationCategory chosen))
            {
                Console.Error.WriteLine($"'{categoryText}' is not a kind of title. Run 'param --list' for the kinds.");
                return 1;
            }
            document["applicationCategoryType"] = (int)chosen;
        }

        bool apply = HasFlag(args, "--apply");
        IReadOnlyList<string> completed = apply ? ParamJson.Complete(document) : [];

        ParamReport report = ParamJson.Check(document);
        Console.WriteLine($"  {"kind",-30} {(report.Category is null ? "unrecognised" : ApplicationCategories.Describe((int)report.Category))}");
        Console.WriteLine();

        bool anyFillable = false;
        foreach (ParamIssue issue in report.Issues)
        {
            string mark = issue.Level == ParamIssueLevel.Fault ? "wrong" : "incomplete";
            Console.WriteLine($"  {issue.Field,-30} {mark,-10} {issue.Message}");
            anyFillable |= issue.CanComplete;
        }
        if (report.Issues.Count == 0)
            Console.WriteLine("  Nothing missing.");

        if (!apply)
        {
            if (anyFillable)
            {
                Console.WriteLine();
                Console.WriteLine("Run again with --apply to fill in what is missing.");
            }
            return report.IsValid ? 0 : 1;
        }

        if (completed.Count == 0 && categoryText is null)
        {
            Console.WriteLine();
            Console.WriteLine("Nothing to write.");
            return report.IsValid ? 0 : 1;
        }

        WriteParamJson(paramPath, document);
        Console.WriteLine();
        Console.WriteLine($"Wrote {paramPath}" +
            (completed.Count > 0 ? $" ({string.Join(", ", completed)})" : string.Empty));
        return report.IsValid ? 0 : 1;
    }

    // Settles the system version an application requires. A module records the system it was built
    // against, and an application that ships it has to require at least as much: the system installs
    // an application whose requirement is too low and then fails to load the module.
    private static int RunSysVer(string[] args)
    {
        string? folder = GetOption(args, "--folder");
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            Console.Error.WriteLine("Usage: sysver --folder <module-folder> [--policy match|upgrade|downgrade|keep] [--version NN.NN] [--apply]");
            return 1;
        }

        string policyName = GetOption(args, "--policy") ?? "match";
        if (!Enum.TryParse(policyName, ignoreCase: true, out SystemVersionPolicy policy))
        {
            Console.Error.WriteLine($"Unknown policy '{policyName}'. Use match, upgrade, downgrade or keep.");
            return 1;
        }

        SystemVersion target = default;
        string? versionText = GetOption(args, "--version");
        if (versionText is not null && !SystemVersion.TryParse(versionText, out target))
        {
            Console.Error.WriteLine($"'{versionText}' is not a system version. Use MM.mm, for example 11.20.");
            return 1;
        }

        string paramPath = Path.Combine(folder, "sce_sys", "param.json");
        JsonObject? document = ReadParamJson(paramPath);
        // Read the requirement only when it is actually a string; a hand-edited file could hold a number
        // or other type there, and GetValue<string> would throw on it.
        string? current = document?["requiredSystemSoftwareVersion"] is JsonValue currentNode
            && currentNode.TryGetValue(out string? currentValue) ? currentValue : null;

        SystemVersionPlan plan;
        try
        {
            plan = SystemVersionPlanner.Plan(folder, current, policy, target);
        }
        catch (ArgumentException ex)
        {
            // The message is written for a person; the parameter name it carries is for a caller.
            int suffix = ex.Message.IndexOf(" (Parameter", StringComparison.Ordinal);
            Console.Error.WriteLine(suffix < 0 ? ex.Message : ex.Message[..suffix]);
            return 1;
        }

        foreach (ModuleRequirement module in plan.Modules)
            Console.WriteLine($"  {module.FileName,-32} {(module.Version.HasValue ? module.Version.ToString() : "no requirement")}");
        foreach (string name in plan.Unreadable)
            Console.WriteLine($"  {name,-32} unreadable");
        if (plan.Modules.Count > 0 || plan.Unreadable.Count > 0)
            Console.WriteLine();

        Console.WriteLine($"Current:  {Show(plan.Current)}");
        Console.WriteLine($"Modules:  {Show(plan.Needed)}");
        Console.WriteLine($"Result:   {Show(plan.Result)}  {plan.Result.ToPackageValue()}");

        foreach (string message in plan.Messages)
            Console.WriteLine($"  {message}");

        if (!HasFlag(args, "--apply"))
            return plan.Unloadable.Count > 0 ? 4 : 0;

        if (document is null)
        {
            Console.Error.WriteLine($"No application metadata to write: {paramPath} was not found.");
            return 1;
        }
        // The version a title states it was built against is the one its modules settle on. It is a
        // separate field from the requirement and is not covered by the plan's own change check, so a
        // title whose requirement was already right would otherwise keep stating it was built against
        // nothing.
        string? built = plan.Result.HasValue ? plan.Result.ToPackageValue() : null;
        bool statesBuild = built is null
            || (document["sdkVersion"] is JsonValue stated
                && stated.TryGetValue(out string? statedText) && statedText == built);

        if (!plan.Changed && statesBuild)
        {
            Console.WriteLine("Nothing to write.");
            return plan.Unloadable.Count > 0 ? 4 : 0;
        }

        if (plan.Changed)
            document["requiredSystemSoftwareVersion"] = plan.Result.ToPackageValue();
        if (built is not null)
            document["sdkVersion"] = built;
        WriteParamJson(paramPath, document);
        Console.WriteLine($"Wrote {paramPath}");
        return plan.Unloadable.Count > 0 ? 4 : 0;

        static string Show(SystemVersion v) => v.HasValue ? v.ToString() : "none";
    }

    private static JsonObject? ReadParamJson(string path)
    {
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonNode.Parse(File.ReadAllText(path)) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // Written back the way the document is read elsewhere: two-space indentation, UTF-8 with no
    // byte-order mark, and the keys left in the order they were parsed in.
    private static void WriteParamJson(string path, JsonObject document)
    {
        var options = new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        File.WriteAllText(path, document.ToJsonString(options), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    // Writes the start object: the entry point the linker includes ahead of the compiled object.
    private static int RunCrt(string[] args)
    {
        string? outPath = GetOption(args, "--out");
        if (string.IsNullOrEmpty(outPath))
        {
            Console.Error.WriteLine("Usage: crt --out <file.o>");
            return 1;
        }
        string full = Path.GetFullPath(outPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, CrtEmitter.BuildStartObject());
        Console.WriteLine($"Wrote {full} (start object).");
        return 0;
    }

    private static int RunCompat(string[] args)
    {
        string? outPath = GetOption(args, "--out");
        if (string.IsNullOrEmpty(outPath))
        {
            Console.Error.WriteLine("Usage: compat --out <file.o>");
            return 1;
        }
        string full = Path.GetFullPath(outPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, CompatEmitter.BuildObject());
        Console.WriteLine($"Wrote {full} (runtime-support compat object).");
        return 0;
    }

    private static PrxBinding ParseBinding(string line)
    {
        int split = line.IndexOfAny(['=', ':']);
        if (split < 0)
            return new PrxBinding(line.Trim(), "", []);

        string name = line[..split].Trim();
        string signature = line[(split + 1)..].Trim();
        int open = signature.IndexOf('(');
        if (open < 0)
            return new PrxBinding(name, signature, []);

        string returnType = signature[..open].Trim();
        int close = signature.IndexOf(')', open + 1);
        string inside = close > open ? signature[(open + 1)..close] : signature[(open + 1)..];
        var parameters = new List<string>();
        foreach (string part in inside.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            parameters.Add(part);
        return new PrxBinding(name, returnType, parameters);
    }

    private static string SanitizeIdentifier(string value)
    {
        var sb = new StringBuilder();
        foreach (char c in value)
            sb.Append(char.IsLetterOrDigit(c) ? c : '_');
        string result = sb.ToString();
        return result.Length > 0 && char.IsLetter(result[0]) ? result : "Module" + result;
    }

    // The tool's build version, for a build log to record which toolchain produced a module.
    private static string ToolVersion()
    {
        Assembly assembly = typeof(Program).Assembly;
        string? informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        string version = informational ?? assembly.GetName().Version?.ToString() ?? "unknown";
        return $"sharpprospero-bindgen {version}";
    }

    // The full options of one command, shown for "<command> --help".
    private static void PrintVerbUsage(string verb)
    {
        switch (verb)
        {
            case "prx":
                Console.WriteLine("Usage: prx --module <file.prx> --inspect");
                Console.WriteLine("       prx --module <file.prx> --names <file> [--class N] [--namespace NS] [--out F.cs] [--strict]");
                Console.WriteLine("  Emits C# interop for the named exports. --strict fails when a name is not exported.");
                break;
            case "stub":
                Console.WriteLine("Usage: stub --lib <libraryName> --names <file> --out <file.a>");
                Console.WriteLine("       stub --module <file.prx> --names <file> --out <file.a>");
                Console.WriteLine("  --lib assumes the usual module and library versions; --module reads them from the module.");
                break;
            case "crt":
                Console.WriteLine("Usage: crt --out <file.o>    Writes the start object that carries the program entry point.");
                break;
            case "compat":
                Console.WriteLine("Usage: compat --out <file.o>    Writes the compatibility object bridging the runtime's C calls.");
                break;
            case "nid":
                Console.WriteLine("Usage: nid --name <symbol> [--name <symbol> ...] | nid --names <file>");
                break;
            case "elf":
                Console.WriteLine("Usage: elf --file <module> [--exports]    Prints an ELF module's header (and its exports).");
                Console.WriteLine("       elf --file <module> --sizes | --symbols | --strings [--min N] | --strip --out <file>");
                Console.WriteLine("  Reports the loadable size, the dynamic symbols, the printable strings, or writes a smaller stripped module.");
                break;
            case "modules":
                Console.WriteLine("Usage: modules --module <eboot.bin> --folder <sce_module folder> [--source <folder>]");
                Console.WriteLine("  Checks that every module the application has to carry travels with it, gathers any");
                Console.WriteLine("  missing from --source, and fails when one is neither present nor available.");
                break;
            case "shader":
                Console.WriteLine("Usage: shader --file <shader.sb> [--registers]");
                Console.WriteLine("  Reports a compiled shader's kind, version, sizes, and register writes.");
                break;
            case "vag":
                Console.WriteLine("Usage: vag --input <clip.wav|clip.vag> --output <clip.vag|clip.wav> [--name <name>]");
                Console.WriteLine("  Converts a 16-bit PCM WAV to VAG (compact sound-effect audio), or a VAG back to WAV.");
                break;
            case "diff":
                Console.WriteLine("Usage: diff --a <module> --b <module>    Reports the exports added, removed, and moved from A to B.");
                break;
            case "gnf":
                Console.WriteLine("Usage: gnf --input <image.png|.tga|.bmp> --output <file.gnf> [--srgb] [--resize WxH]");
                Console.WriteLine("       gnf --info <file.gnf>    Reports a GNF's header and first texture.");
                Console.WriteLine("  Builds a linear texture the graphics processor samples. --srgb marks the colour channels sRGB; --resize scales first.");
                break;
            case "payload":
                Console.WriteLine("Usage: payload --send --host <address> [--port 9021] --file <payload.elf>");
                Console.WriteLine("  Sends a payload built with 'link --kind payload' to a listening loader.");
                break;
            case "self":
                Console.WriteLine("Usage: self --inspect --file <file>");
                Console.WriteLine("       self --sign --in <file.elf|.prx> --out <file.self|.sprx> [--app-version 0xNN] [--fw-version 0xNN] [--authority 0xNN] [--no-normalize]");
                Console.WriteLine("       self --extract --in <file.self|.sprx> --out <file.elf|.prx>");
                break;
            case "offsets":
                Console.WriteLine("Usage: offsets --file <module> [--firmware NN.NN] [--coverage] [--library <name>] [--text]");
                break;
            case "retarget":
                Console.WriteLine("Usage: retarget --file <module.prx|.sprx> [--to NN.NN] [--set-lib-version <name>=0xNNNN ...] [--out <file>]");
                break;
            case "param":
                Console.WriteLine("Usage: param --folder <module-folder> [--category <kind>] [--apply]");
                Console.WriteLine("       param --list    Lists the kinds of title and their numbers.");
                Console.WriteLine("  Reports what the application's metadata gets wrong and what a finished title carries that");
                Console.WriteLine("  it does not. --apply fills in the missing fields; --category sets the kind of title.");
                break;
            case "sysver":
                Console.WriteLine("Usage: sysver --folder <module-folder> [--policy match|upgrade|downgrade|keep] [--version NN.NN] [--apply]");
                break;
            case "link":
                Console.WriteLine("Usage: link --obj <file.o> [--obj ...] [--lib <archive.a> ...] [--stub <stub.o> ...] [--self-contained]");
                Console.WriteLine("            [--kind eboot|prx|payload] [--entry <symbol>] [--export <name> ...]");
                Console.WriteLine("            [--publish-name <name>] [--export-library <name>] --out <module>");
                Console.WriteLine("  --self-contained supplies the start object and the core module stubs.");
                break;
            default:
                PrintUsage();
                break;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: sharpprospero-bindgen [options]");
        Console.WriteLine("       sharpprospero-bindgen prx --module <file.prx> --inspect");
        Console.WriteLine("       sharpprospero-bindgen prx --module <file.prx> --names <file> [--class N --namespace NS --out F.cs --strict]");
        Console.WriteLine("       sharpprospero-bindgen stub --lib <libraryName> --names <file> --out <file.a>");
        Console.WriteLine("       sharpprospero-bindgen crt --out <file.o>");
        Console.WriteLine("       sharpprospero-bindgen compat --out <file.o>");
        Console.WriteLine("       sharpprospero-bindgen link [--self-contained] --obj <file.o> [--lib <archive.a>] [--kind eboot|prx|payload] [--entry <sym>] [--export <name>] --out <module>");
        Console.WriteLine("       sharpprospero-bindgen elf --file <module> [--exports]");
        Console.WriteLine("       sharpprospero-bindgen diff --a <module> --b <module>");
        Console.WriteLine("       sharpprospero-bindgen modules --module <eboot.bin> --folder <sce_module folder> [--source <folder>]");
        Console.WriteLine("       sharpprospero-bindgen shader --file <shader.sb> [--registers]");
        Console.WriteLine("       sharpprospero-bindgen vag --input <clip.wav|clip.vag> --output <clip.vag|clip.wav> [--name <name>]");
        Console.WriteLine("       sharpprospero-bindgen gnf --input <image.png|.tga|.bmp> --output <file.gnf> [--srgb]");
        Console.WriteLine("       sharpprospero-bindgen payload --send --host <address> [--port 9021] --file <payload.elf>");
        Console.WriteLine("       sharpprospero-bindgen self --inspect --file <file>");
        Console.WriteLine("       sharpprospero-bindgen self --sign --in <file.elf|.prx> --out <file.self|.sprx> [--app-version 0xNN --fw-version 0xNN --authority 0xNN --no-normalize]");
        Console.WriteLine("       sharpprospero-bindgen self --extract --in <file.self|.sprx> --out <file.elf|.prx>");
        Console.WriteLine("       sharpprospero-bindgen offsets --file <module> [--firmware NN.NN] [--coverage] [--library <name>] [--text]");
        Console.WriteLine("       sharpprospero-bindgen retarget --file <module> [--to NN.NN] [--set-lib-version <name>=0xNNNN] [--out <file>]");
        Console.WriteLine("       sharpprospero-bindgen nid --name <symbol>");
        Console.WriteLine("       sharpprospero-bindgen sysver --folder <module-folder> [--policy P --version NN.NN --apply]");
        Console.WriteLine("       sharpprospero-bindgen param --folder <module-folder> [--category <kind>] [--apply] | param --list");
        Console.WriteLine();
        Console.WriteLine("Run '<command> --help' for a command's full options, or --version for the tool version.");
        Console.WriteLine();
        Console.WriteLine("sysver settles the system version an application requires against the modules it ships:");
        Console.WriteLine("  --policy match        Require what the modules need. Never lowers. The default.");
        Console.WriteLine("  --policy upgrade      Raise the requirement to --version.");
        Console.WriteLine("  --policy downgrade    Lower the requirement to --version, and report what stops loading.");
        Console.WriteLine("  --policy keep         Leave it alone, and report a module that needs more.");
        Console.WriteLine("  --apply               Write the result to sce_sys/param.json. Prints the plan without it.");
        Console.WriteLine();
        Console.WriteLine("  --sdk <folder>        SDK include tree. Default: %PROSPERO_SDK_DIR%/target/include.");
        Console.WriteLine("  --out <folder>        Output folder for generated bindings.");
        Console.WriteLine("  --modules <file>      Module catalog. Default: modules.json next to the tool.");
        Console.WriteLine("  --responses <folder>  Where response files are written. Default: <out>/responses.");
    }
}
