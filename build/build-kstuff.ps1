#requires -Version 5.1
<#
.SYNOPSIS
    Builds the complete kstuffSharp deliverable end-to-end.

.DESCRIPTION
    kstuffSharp is a two-part payload: an installer that runs in kernel context
    to bring up the kernel module, and a loader that maps the installer at a
    hint address and calls its entry point. The loader embeds the installer as
    a byte array in InstallerBlob.g.cs.

    A complete build therefore runs three steps in sequence:
      1. Build the installer payload (samples/kstuffSharp-installer/InstallerApp.csproj).
      2. Regenerate samples/kstuffSharp/InstallerBlob.g.cs from the fresh installer ELF.
      3. Build the loader payload (samples/kstuffSharp/SampleApp.csproj), which
         now embeds the just-built installer.

    Any change to shared kernel code (SharpProspero/Payload/Kernel/*) must go
    through this script — building only the loader would embed the previous
    installer bytes.

.PARAMETER SdkRoot
    The SharpProspero SDK folder. Defaults to the parent folder of this script.

.PARAMETER Configuration
    Build configuration. Default: Release.

.PARAMETER DiagnosticBreadcrumbs
    When set, both payloads emit the diagnostic breadcrumb call sites and their
    rodata strings. Off by default; the resulting ELFs are unchanged production
    builds otherwise.
#>
param(
    [string]$SdkRoot = "",
    [string]$Configuration = "Release",
    [switch]$DiagnosticBreadcrumbs
)

$ErrorActionPreference = "Stop"

if (-not $SdkRoot) { $SdkRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$SdkRoot = (Resolve-Path $SdkRoot).Path

$buildScript = Join-Path $SdkRoot "build/build-app.ps1"
if (-not (Test-Path $buildScript)) { throw "build-app.ps1 not found at $buildScript" }

$installerProject = Join-Path $SdkRoot "samples/kstuffSharp-installer/InstallerApp.csproj"
$loaderProject    = Join-Path $SdkRoot "samples/kstuffSharp/SampleApp.csproj"
$installerElf     = Join-Path $SdkRoot "samples/kstuffSharp-installer/out/InstallerApp.elf"
$installerBlob    = Join-Path $SdkRoot "samples/kstuffSharp/InstallerBlob.g.cs"

if (-not (Test-Path $installerProject)) { throw "Installer project not found at $installerProject" }
if (-not (Test-Path $loaderProject))    { throw "Loader project not found at $loaderProject" }

# 1. Build the installer payload.
Write-Host ""
Write-Host "==================== 1/3 Installer payload ===================="
$installerArgs = @("-ExecutionPolicy", "Bypass", "-File", $buildScript,
                   "-ProjectPath", $installerProject,
                   "-Configuration", $Configuration,
                   "-Payload")
if ($DiagnosticBreadcrumbs) { $installerArgs += "-DiagnosticBreadcrumbs" }
& powershell @installerArgs
if ($LASTEXITCODE -ne 0) { throw "Installer build failed with exit code $LASTEXITCODE" }
if (-not (Test-Path $installerElf)) { throw "Installer ELF not produced at $installerElf" }

# 2. Regenerate InstallerBlob.g.cs from the fresh installer ELF. The loader's
#    source tree embeds this file directly so the AOT compile inlines the
#    installer bytes into the loader's .rodata section, matching the reference
#    project's .incbin embedding of the raw payload blob.
Write-Host ""
Write-Host "==================== 2/3 Embed installer ======================"
$bytes = [System.IO.File]::ReadAllBytes($installerElf)
$sb = [System.Text.StringBuilder]::new(($bytes.Length * 5) + 256)
[void]$sb.AppendLine("// Auto-generated. Do not edit.")
[void]$sb.AppendLine("namespace SampleApp;")
[void]$sb.AppendLine("internal static class InstallerBlob")
[void]$sb.AppendLine("{")
[void]$sb.AppendLine("    public static System.ReadOnlySpan<byte> Data => new byte[]")
[void]$sb.AppendLine("    {")
for ($i = 0; $i -lt $bytes.Length; $i++) {
    if ($i % 32 -eq 0) {
        if ($i -gt 0) { [void]$sb.AppendLine() }
        [void]$sb.Append("        ")
    }
    [void]$sb.AppendFormat("0x{0:X2}", $bytes[$i])
    if ($i -lt $bytes.Length - 1) { [void]$sb.Append(",") }
}
[void]$sb.AppendLine()
[void]$sb.AppendLine("    };")
[void]$sb.AppendLine("}")
[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($installerBlob),
    $sb.ToString(),
    [System.Text.UTF8Encoding]::new($false))
Write-Host "  Embedded $($bytes.Length) bytes into $installerBlob"

# 3. Build the loader payload. It will pick up the freshly-embedded installer
#    from InstallerBlob.g.cs during its AOT compile.
Write-Host ""
Write-Host "==================== 3/3 Loader payload ========================"
$loaderArgs = @("-ExecutionPolicy", "Bypass", "-File", $buildScript,
                "-ProjectPath", $loaderProject,
                "-Configuration", $Configuration,
                "-Payload")
if ($DiagnosticBreadcrumbs) { $loaderArgs += "-DiagnosticBreadcrumbs" }
& powershell @loaderArgs
if ($LASTEXITCODE -ne 0) { throw "Loader build failed with exit code $LASTEXITCODE" }

$loaderElf = Join-Path $SdkRoot "samples/kstuffSharp/out/SampleApp.elf"
$installerSize = (Get-Item $installerElf).Length
$loaderSize    = (Get-Item $loaderElf).Length

Write-Host ""
Write-Host "==================== Complete =================================="
Write-Host "  Installer: $installerElf ($installerSize bytes)"
Write-Host "  Loader:    $loaderElf ($loaderSize bytes)"
Write-Host ""
Write-Host "Send the loader to a listening loader with:"
Write-Host "  dotnet run --project `"$SdkRoot/tools/SharpProspero.Bindings.Generator`" -- payload --send --host <address> --file `"$loaderElf`""
