#requires -Version 5.1
<#
.SYNOPSIS
    Builds a SharpProspero application and writes either an installable package or a plain folder.

.DESCRIPTION
    Compile the C# to an object, link it into the module with the ahead-of-time runtime, gather the
    module and its metadata, then either pack the result or leave the files as they are. Everything the
    link needs is produced by the toolchain and the .NET SDK; no runtime pack or outside tool is set up.

    The compile step (`dotnet publish -r linux-x64`) has to run on a Linux host, because that is where
    the ahead-of-time compiler emits an object for the device instruction set. On Windows this script
    runs that one step through WSL automatically, so a Windows user builds without switching hosts; the
    rest of the build is the toolchain itself and runs wherever the script is started.

.PARAMETER ProjectPath
    The application project to build.

.PARAMETER Output
    Package writes an installable *.pkg (the default). Folder leaves every file in one folder.

.PARAMETER OutputFolder
    Where the result is written. Defaults to an 'out' folder next to the project.

.PARAMETER Configuration
    Build configuration. Default: Release.

.PARAMETER SystemVersionPolicy
    How the system version the application requires is settled against the modules it ships.

.PARAMETER SystemVersion
    The version Upgrade and Downgrade move to, as NN.NN (for example 11.20).

.PARAMETER SdkRoot
    The SharpProspero SDK folder. Defaults to the folder above this script, then SHARPPROSPERO_ROOT.

.PARAMETER TitleId
    The title this build carries, when it should differ from the one the project's metadata names.
    Installers generally treat a title already on the machine as present and decline to replace it, so
    a build meant to sit beside the last one needs a title of its own. Only the gathered copy changes.
#>
param(
    [Parameter(Mandatory = $true)][string]$ProjectPath,
    [ValidateSet("Package", "Folder")][string]$Output = "Package",
    [string]$OutputFolder = "",
    [string]$Configuration = "Release",
    [ValidateSet("Match", "Upgrade", "Downgrade", "Keep")][string]$SystemVersionPolicy = "Match",
    [string]$SystemVersion = "",
    [string]$SdkRoot = "",
    [string]$TitleId = "",
    [switch]$Payload,
    [switch]$DiagnosticBreadcrumbs
)

$ErrorActionPreference = "Stop"
$rid = "linux-x64"

if (-not $SdkRoot) { $SdkRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
if (-not (Test-Path (Join-Path $SdkRoot "build/Prospero.App.targets")) -and $env:SHARPPROSPERO_ROOT) {
    $SdkRoot = $env:SHARPPROSPERO_ROOT
}
# A project created from a sample points its imports and its reference to the SDK through the
# SharpProsperoRoot property (defaulting to the SHARPPROSPERO_ROOT environment variable). The in-tree
# sample uses relative imports and does not need it, but an external project does, so the resolved SDK
# folder is passed to every compile and evaluate step below. Resolve it to a full path first.
$SdkRoot = (Resolve-Path $SdkRoot).Path

$projectDir = Split-Path -Parent (Resolve-Path $ProjectPath)
if (-not $OutputFolder) { $OutputFolder = Join-Path $projectDir "out" }
# Settled to a full path before anything derives from it. Left relative, it means different places to
# different steps: the compile and link steps resolve it against the project, everything after against
# wherever the script was started. A build given a relative folder linked the module into one place and
# then signed and packaged whatever happened to be in the other, which is silently the wrong artefact.
if (-not [System.IO.Path]::IsPathRooted($OutputFolder)) {
    $OutputFolder = Join-Path (Get-Location).Path $OutputFolder
}
$OutputFolder = [System.IO.Path]::GetFullPath($OutputFolder)
$moduleFolder = Join-Path $OutputFolder "module"

$onWindows = [System.Environment]::OSVersion.Platform -eq "Win32NT"
$haveWsl = $onWindows -and (Get-Command wsl.exe -ErrorAction SilentlyContinue)

# A Windows path as WSL sees it: C:\a\b -> /mnt/c/a/b.
function ConvertTo-WslPath([string]$p) {
    $full = [System.IO.Path]::GetFullPath($p)
    $drive = $full.Substring(0, 1).ToLowerInvariant()
    return "/mnt/$drive" + ($full.Substring(2) -replace '\\', '/')
}

# 1. Compile the C# to an object for the device instruction set. On Windows the ahead-of-time compiler
# cannot cross-compile, so the publish runs in WSL; the object still lands in the project's obj folder,
# which both sides share.
#
# The publish's own last step tries to link the object into a host executable and fails, because the
# device service functions the module imports (scePad*, sceVideoOut*, ...) are not present on the build
# host — the SDK's linker resolves those against the device modules. The object the compiler writes just
# before that link is exactly what is needed, so a non-zero publish result is expected; the object's
# presence is the real check.
Write-Host "== Compile =="
# Name the object the project produces, and clear any object a previous build left behind. The publish
# below ends in a host link that is expected to fail (the device modules are absent on the build host),
# so its exit code cannot signal success; the freshly written object is the real check. Removing the
# stale object first means a compile that fails before writing it (a source error) is caught here rather
# than silently linking the old one.
$targetName = (& dotnet msbuild $ProjectPath -getProperty:TargetName `
    -p:Configuration=$Configuration -p:RuntimeIdentifier=$rid "-p:SharpProsperoRoot=$SdkRoot" --nologo | Out-String).Trim()
if (-not $targetName) { throw "Could not resolve the project's target name." }
# Which kind of module the project asks for decides which run-time bring-up object is gathered below,
# so it is read here alongside the name rather than guessed from the file that comes out.
$moduleKind = (& dotnet msbuild $ProjectPath -getProperty:ProsperoModuleKind `
    -p:Configuration=$Configuration -p:RuntimeIdentifier=$rid "-p:SharpProsperoRoot=$SdkRoot" --nologo | Out-String).Trim()
if (-not $moduleKind) { $moduleKind = "Executable" }
$objectPath = Join-Path $projectDir "obj/$Configuration/net10.0/$rid/native/$targetName.o"
if (Test-Path $objectPath) { Remove-Item $objectPath -Force }

# The publish always ends in that failed host link, so its output would report an error on every
# successful build. Keep it and show it only when the object is missing, which is the real failure.
if ($onWindows) {
    if (-not $haveWsl) {
        throw "The compile step needs a Linux host. Install WSL (wsl --install) so this runs automatically, or build on Linux."
    }
    $wslProject = ConvertTo-WslPath $ProjectPath
    $wslSdk = ConvertTo-WslPath $SdkRoot
    $publishLog = (& wsl.exe -e bash -lc "dotnet publish '$wslProject' -c $Configuration -r $rid -p:SharpProsperoRoot='$wslSdk' --nologo" 2>&1 | Out-String)
} else {
    $publishLog = (& dotnet publish $ProjectPath -c $Configuration -r $rid "-p:SharpProsperoRoot=$SdkRoot" --nologo 2>&1 | Out-String)
}

if (-not (Test-Path $objectPath)) {
    Write-Host $publishLog
    throw "No compiled object was produced at $objectPath. The ahead-of-time compile did not run to completion; the publish output above shows why."
}
Write-Host "  Compiled $targetName.o for $rid."


# 2. Gather the ahead-of-time runtime archives. They are restored by the publish above (the .NET SDK's
# NativeAOT runtime pack), so they are found in the package cache rather than assembled by hand. On
# Windows the cache lives in WSL, so the archives are copied out to the project's obj folder.
Write-Host "== Runtime support =="
# An application reaches the run-time initialiser from the main the application bring-up object
# defines; a library has no main, so it takes the library bring-up object, which runs the initialiser
# from its own constructor list. Gathering the wrong one leaves the module's exports entering a run
# time nothing has started.
$bootstrapper = if ($moduleKind -eq "Prx") { "libbootstrapperdll.o" } else { "libbootstrapper.o" }
$archiveNames = @(
    $bootstrapper, "libRuntime.WorkstationGC.a", "libRuntime.VxsortDisabled.a",
    "libeventpipe-disabled.a", "libstandalonegc-disabled.a", "libaotminipal.a", "libstdc++compat.a",
    "libSystem.Native.a", "libz.a", "libbrotlienc.a", "libbrotlidec.a", "libbrotlicommon.a",
    "libSystem.IO.Compression.Native.a"
)
$supportDir = Join-Path $projectDir "obj/$Configuration/net10.0/$rid/runtime-support"
New-Item -ItemType Directory -Force -Path $supportDir | Out-Null

# Which runtime pack to gather from is not a guess: the compile step already recorded which one it
# restored and where the cache is. Reading that beats taking the newest directory in the cache, which
# is the wrong pack as soon as more than one is present - and was chosen by name order rather than by
# version, so a 10.0.9 sorts after a 10.0.10 and the older one quietly won. Archives from one pack
# linked against an object compiled for another is the kind of mismatch that surfaces far from here.
$assetsPath = Join-Path $projectDir "obj/project.assets.json"
if (-not (Test-Path $assetsPath)) {
    throw "No restore record at $assetsPath. Run the compile step once so the runtime pack is restored."
}
$assets = Get-Content -Raw $assetsPath | ConvertFrom-Json
$packName = "Microsoft.NETCore.App.Runtime.NativeAOT.$rid"
$packVersion = $null
foreach ($framework in $assets.project.frameworks.PSObject.Properties) {
    foreach ($dep in $framework.Value.downloadDependencies) {
        # The range reads "[x.y.z, x.y.z]"; both ends name the same version.
        if ($dep.name -eq $packName) { $packVersion = ($dep.version -replace '[\[\]\s]', '').Split(',')[0] }
    }
}
if (-not $packVersion) { throw "$packName is not named in $assetsPath; the compile step did not restore it." }

# The compile runs where the compiler for the device instruction set runs, and restores into that
# host's cache - so on Windows the folder the record names is a path only the other host can see, and
# the copy has to be made from there.
$packTail = "$($packName.ToLowerInvariant())/$packVersion/runtimes/$rid/native"
$nativeDir = $null
$fromOtherHost = $false
foreach ($folder in $assets.packageFolders.PSObject.Properties.Name) {
    $candidate = "$($folder.TrimEnd('/','\'))/$packTail"
    if (Test-Path $candidate) { $nativeDir = $candidate; break }
    if ($haveWsl -and $folder.StartsWith("/")) {
        $seen = (& wsl.exe -e bash -lc "test -d '$candidate' && echo yes" | Out-String).Trim()
        if ($seen -eq "yes") { $nativeDir = $candidate; $fromOtherHost = $true; break }
    }
}
if (-not $nativeDir) {
    throw "The restore names $packName $packVersion, but its files are in none of the recorded package folders."
}
Write-Host "  Runtime pack $packVersion"
if ($fromOtherHost) {
    $wslSupport = ConvertTo-WslPath $supportDir
    $copy = "set -e; for n in $($archiveNames -join ' '); do cp `"$nativeDir/`$n`" '$wslSupport/' 2>/dev/null || true; done"
    & wsl.exe -e bash -lc $copy
} else {
    foreach ($n in $archiveNames) {
        $src = Join-Path $nativeDir $n
        if (Test-Path $src) { Copy-Item -Force $src (Join-Path $supportDir $n) }
    }
}
if (-not (Get-ChildItem -Path $supportDir -File -ErrorAction SilentlyContinue)) {
    throw "No runtime archives were gathered into $supportDir."
}

# A payload is a position-independent executable a loader maps and runs in an existing process. It links
# to a single .elf with the payload output kind, resolves its outside references at run time, and is not
# packaged, so the module link, the metadata, and the packaging steps below are skipped.
if ($Payload) {
    Write-Host "== Link (payload) =="
    $name = [System.IO.Path]::GetFileNameWithoutExtension($ProjectPath)
    New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null
    $elf = Join-Path $OutputFolder "$name.elf"

    # Extract ProsperoSprx ItemGroup entries from the project. Each entry becomes a --sprx flag
    # so the linker emits DT_NEEDED for the declared SPRX modules. Samples that declare no
    # <ProsperoSprx> items get the three defaults (libkernel_web, libSceLibcInternal, libSceNet).
    $sprxItems = @()
    try {
        $sprxRaw = (& dotnet msbuild $ProjectPath -getItem:ProsperoSprx `
            -p:Configuration=$Configuration -p:RuntimeIdentifier=$rid "-p:SharpProsperoRoot=$SdkRoot" --nologo 2>$null | Out-String).Trim()
        if ($sprxRaw) {
            $sprxParsed = $sprxRaw | ConvertFrom-Json
            # MSBuild 18.x wraps -getItem output in {"Items":{"ProsperoSprx":[...]}};
            # older versions may return a bare array. Handle both.
            $arr = if ($sprxParsed.Items) { $sprxParsed.Items.ProsperoSprx } else { $sprxParsed }
            if ($arr) {
                foreach ($item in $arr) {
                    $sprxItems += $item.Identity
                }
            }
        }
    } catch {
        # Silently ignore: older MSBuild versions may not support -getItem.
    }
    if ($sprxItems.Count -gt 0) {
        Write-Host "  SPRX: $($sprxItems -join ', ')"
    }

    # Extract ProsperoKernelSprx from the project. When set, it replaces the default
    # libkernel_web.sprx with a different kernel module (e.g. libkernel_sys.sprx for
    # process-level payloads like the SDK samples/mntinfo and samples/hwinfo).
    $kernelSprx = ""
    try {
        $kernelSprx = (& dotnet msbuild $ProjectPath -getProperty:ProsperoKernelSprx `
            -p:Configuration=$Configuration -p:RuntimeIdentifier=$rid "-p:SharpProsperoRoot=$SdkRoot" --nologo 2>$null | Out-String).Trim()
    } catch { }
    if ($kernelSprx) {
        Write-Host "  Kernel SPRX: $kernelSprx"
    }

    # Every payload links the full CRT and all runtime archives. There are no profile tiers.
    $linkArgs = @("link", "--kind", "payload", "--self-contained", "--obj", $objectPath)
    foreach ($s in $sprxItems) { $linkArgs += @("--sprx", $s) }
    if ($kernelSprx) { $linkArgs += @("--kernel-sprx", $kernelSprx) }
    # The payload CRT supplies its own start sequence.  libbootstrapper.o is included because it
    # provides the NativeAOT runtime bootstrap (RhInitialize, RhRegisterOSModule, InitializeModules)
    # that must run before the managed entry point.  Its main() calls __managed__Main, which the
    # sample's [UnmanagedCallersOnly(EntryPoint = "__managed__Main")] exports.
    # libbootstrapperdll.o is the DLL-mode bootstrapper (PRX modules) and is excluded.
    foreach ($o in Get-ChildItem -Path $supportDir -File -Filter *.o) {
        if ($o.Name -eq 'libbootstrapperdll.o') { continue }
        $linkArgs += @("--obj", $o.FullName)
    }
    foreach ($a in Get-ChildItem -Path $supportDir -File -Filter *.a) { $linkArgs += @("--lib", $a.FullName) }
    if ($DiagnosticBreadcrumbs) { $linkArgs += @("--diagnostics") }
    $linkArgs += @("--out", $elf)
    & dotnet run --project (Join-Path $SdkRoot "tools/SharpProspero.Bindings.Generator/SharpProspero.Bindings.Generator.csproj") `
        -c $Configuration -- @linkArgs
    if ($LASTEXITCODE -ne 0) { throw "Payload link failed." }
    Write-Host "== Done =="
    Write-Host "Payload written to $elf"
    Write-Host "Send it to a listening loader with:"
    Write-Host "  dotnet run --project `"$SdkRoot/tools/SharpProspero.Bindings.Generator`" -- payload --send --host <address> --file `"$elf`""
    return
}

# 3. Link the object and the runtime archives into the module. The gathered archives live in one folder,
# so the folder is handed over and the link target picks up every archive in it — no list to pass.
Write-Host "== Link =="
New-Item -ItemType Directory -Force -Path $moduleFolder | Out-Null
& dotnet msbuild $ProjectPath /t:ProsperoLink `
    /p:Configuration=$Configuration `
    /p:ProsperoObjectFile=$objectPath `
    /p:ProsperoRuntimePack=$supportDir `
    /p:OutputPath=$moduleFolder/ `
    "/p:SharpProsperoRoot=$SdkRoot" `
    /nologo
if ($LASTEXITCODE -ne 0) { throw "Link failed." }

# 4. Gather the module's metadata, any modules it ships with, and the app-owned data folders
# (localization strings, per-app resources). Every folder on this list is cleared in the output
# before the copy so a folder the project stopped supplying does not linger from a previous build.
foreach ($folder in @("sce_sys", "sce_module", "strings")) {
    $source = Join-Path $projectDir $folder
    $destination = Join-Path $moduleFolder $folder
    if (Test-Path $destination) { Remove-Item -Recurse -Force $destination }
    if (-not (Test-Path $source)) { continue }
    Copy-Item -Recurse -Force $source $destination
}

# 4a. Emit the compressed texture form the system reader looks for beside every icon*.png and pic*.png
# in the gathered sce_sys folder. Nothing to do when no matching source is present.
$gatheredSceSys = Join-Path $moduleFolder "sce_sys"
if (Test-Path $gatheredSceSys) {
    $hasMedia = @(Get-ChildItem -Path $gatheredSceSys -File -Filter *.png -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(icon|pic)' }).Count -gt 0
    if ($hasMedia) {
        Write-Host "== Textures =="
        & dotnet run --project (Join-Path $SdkRoot "tools/SharpProspero.Bindings.Generator/SharpProspero.Bindings.Generator.csproj") `
            -c $Configuration -- sceassets --folder $gatheredSceSys
        if ($LASTEXITCODE -ne 0) { throw "The system-media texture step failed." }
    }
}

# The title this build carries, when it is not the one the project's own metadata names. Installers
# generally treat a title as already present and refuse to replace it, so a run meant to be installed
# beside the last one needs a title of its own. Only the copy gathered here is changed; the project's
# own metadata is left alone.
if ($TitleId) {
    if ($TitleId -notmatch '^[A-Z]{4}[0-9]{5}$') {
        throw "TitleId must be four letters and five digits, for example PPSA99098; got '$TitleId'."
    }
    $paramPath = Join-Path $moduleFolder "sce_sys/param.json"
    if (-not (Test-Path $paramPath)) { throw "No sce_sys/param.json was gathered, so the title cannot be set." }
    $param = Get-Content -Raw $paramPath | ConvertFrom-Json
    $was = $param.titleId
    $param.titleId = $TitleId
    # The content identifier carries the title in its middle field; the rest of it is left as it was.
    if ($param.contentId -match '^(.{7})[A-Z]{4}[0-9]{5}(.*)$') {
        $param.contentId = "$($Matches[1])$TitleId$($Matches[2])"
    }
    # Written without a byte-order mark. The mark is three bytes the machine's reader has no case for,
    # so it stops at the first one and abandons the whole file. Asking for this encoding by name adds
    # the mark on the older host this script still supports, and the name that would not is newer than
    # that host, so the text is written directly instead.
    [System.IO.File]::WriteAllText(
        $paramPath, ($param | ConvertTo-Json -Depth 32), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  Title $was -> $TitleId"
}

# 4b. Some of the modules an application imports from are not published by the system: the application
# carries its own copy, and one that names such a module without shipping it installs cleanly and then
# hangs the console at launch, with nothing written to the log. The step below gathers what is missing
# from a module folder and stops the build when it cannot, so that package is never produced.
Write-Host "== Modules =="
$sceModuleFolder = Join-Path $moduleFolder "sce_module"
$moduleSource = $env:PROSPERO_MODULES
if (-not $moduleSource) {
    $property = (& dotnet msbuild $ProjectPath -getProperty:ProsperoModuleFolder `
        -p:Configuration=$Configuration "-p:SharpProsperoRoot=$SdkRoot" --nologo | Out-String).Trim()
    if ($property) { $moduleSource = $property }
}
# The modules an application carries are supplied with the SDK, which is where they are taken from
# unless a folder is named. A copy lifted out of an installed application is the wrong thing to ship:
# it was built for whichever system that application shipped against, and the loader binds against it
# before any of the application's own code runs, so a mismatch hangs the console with nothing logged.
if (-not $moduleSource -and $env:SCE_PROSPERO_SDK_DIR) {
    $fromSdk = Join-Path $env:SCE_PROSPERO_SDK_DIR "target/sce_module"
    if (Test-Path $fromSdk) { $moduleSource = $fromSdk }
}
$linkedModule = @(Get-ChildItem -Path $moduleFolder -File |
    Where-Object { $_.Extension -in @(".bin", ".prx", ".elf", ".sprx", ".self") }) | Select-Object -First 1
if ($linkedModule) {
    $modulesArgs = @("modules", "--module", $linkedModule.FullName, "--folder", $sceModuleFolder)
    if ($moduleSource -and (Test-Path $moduleSource)) { $modulesArgs += @("--source", $moduleSource) }
    & dotnet run --project (Join-Path $SdkRoot "tools/SharpProspero.Bindings.Generator/SharpProspero.Bindings.Generator.csproj") `
        -c $Configuration -- @modulesArgs
    if ($LASTEXITCODE -ne 0) { throw "The application is missing a module it has to carry. See the message above." }
}

# 4c. Check the metadata that describes the application to the system. A field carrying a value the
# system does not recognise stops the build; a field a finished title always carries but this one does
# not is filled in. Neither shows up as an error on the console - the home screen simply draws the
# title wrongly, or a service it expected to reach is never offered to it.
if (Test-Path (Join-Path $moduleFolder "sce_sys/param.json")) {
    Write-Host "== Metadata =="
    & dotnet run --project (Join-Path $SdkRoot "tools/SharpProspero.Bindings.Generator/SharpProspero.Bindings.Generator.csproj") `
        -c $Configuration -- param --folder $moduleFolder --apply
    if ($LASTEXITCODE -ne 0) { throw "The application metadata describes the title wrongly. See the message above." }
}

# 5. Settle the system version the application requires. This lives in the application metadata; a
# library module has none (the application that bundles it settles its own version), so the step runs
# only when that metadata is present.
if (Test-Path (Join-Path $moduleFolder "sce_sys/param.json")) {
    Write-Host "== System version =="
    $sysverArgs = @("sysver", "--folder", $moduleFolder, "--policy", $SystemVersionPolicy.ToLowerInvariant(), "--apply")
    if ($SystemVersion) { $sysverArgs += @("--version", $SystemVersion) }
    & dotnet run --project (Join-Path $SdkRoot "tools/SharpProspero.Bindings.Generator/SharpProspero.Bindings.Generator.csproj") `
        -c $Configuration -- @sysverArgs
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 4) { throw "Could not settle the system version." }
}

# 6. Wrap every module in the container the loader expects. A module left as a plain ELF is turned away
# before any of its code runs, so this is what makes the result launchable. The modules the application
# carries are wrapped alongside the one built here: a copy taken from a module folder is an unwrapped
# ELF and is turned away exactly as an unwrapped eboot.bin is. The step leaves an already-wrapped file
# untouched, so re-running a build is safe and a project that ships wrapped modules is handled too.
$builtModules = @(Get-ChildItem -Path $moduleFolder -File) +
    @(Get-ChildItem -Path (Join-Path $moduleFolder "sce_module") -File -ErrorAction SilentlyContinue)
$builtModules = @($builtModules | Where-Object { $_.Extension -in @(".bin", ".prx", ".elf", ".sprx", ".self") })
if ($builtModules.Count -gt 0) {
    Write-Host "== Sign =="
    foreach ($builtModule in $builtModules) {
        & dotnet run --project (Join-Path $SdkRoot "tools/SharpProspero.Bindings.Generator/SharpProspero.Bindings.Generator.csproj") `
            -c $Configuration -- self --sign --in $builtModule.FullName --out $builtModule.FullName
        if ($LASTEXITCODE -ne 0) { throw "Could not wrap $($builtModule.Name) for the loader." }
    }
}

# 7. Either pack the result or leave the folder as the output.
if ($Output -eq "Folder") {
    Write-Host "== Done =="
    Write-Host "Files written to $moduleFolder"
    return
}

Write-Host "== Package =="
$packArgs = @("--in", $moduleFolder, "--out", $OutputFolder)
& dotnet run --project (Join-Path $SdkRoot "tools/SharpProspero.Packager/SharpProspero.Packager.csproj") `
    -c $Configuration -- @packArgs
if ($LASTEXITCODE -ne 0) { throw "Packaging failed." }

Write-Host "Package written to $OutputFolder"
