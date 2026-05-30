[CmdletBinding()]
param(
    [string]$UbuntuIsoPath = "",
    [switch]$DownloadUbuntuIso,
    [switch]$AttachIso,
    [switch]$EnableNatUpdateAdapters
)

$ErrorActionPreference = "Stop"

$workspaceRoot = "C:\NIDS_Workspace"
$scriptPath = Join-Path $workspaceRoot "scripts\build_realistic_virtualbox_lab.ps1"

if (-not (Test-Path $scriptPath)) {
    throw "Lab build script not found: $scriptPath"
}

$arguments = @(
    "-ExecutionPolicy", "Bypass",
    "-File", $scriptPath,
    "-LabRoot", $PSScriptRoot
)

if ($UbuntuIsoPath) {
    $arguments += @("-UbuntuIsoPath", $UbuntuIsoPath)
}

if ($DownloadUbuntuIso) {
    $arguments += "-DownloadUbuntuIso"
}

if ($AttachIso) {
    $arguments += "-AttachIso"
}

if (-not $EnableNatUpdateAdapters) {
    $arguments += "-SkipNatUpdateAdapters"
}

& powershell @arguments
