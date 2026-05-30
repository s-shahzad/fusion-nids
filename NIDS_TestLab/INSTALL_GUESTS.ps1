[CmdletBinding()]
param(
    [string]$IsoPath = "",
    [string]$ScriptTemplatePath = "",
    [switch]$EnableNatUpdateAdapters,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$workspaceRoot = "C:\NIDS_Workspace"
$scriptPath = Join-Path $workspaceRoot "scripts\install_lab_guests.ps1"

if (-not (Test-Path $scriptPath)) {
    throw "Guest install script not found: $scriptPath"
}

$arguments = @(
    "-ExecutionPolicy", "Bypass",
    "-File", $scriptPath,
    "-LabRoot", $PSScriptRoot
)

if ($IsoPath) {
    $arguments += @("-IsoPath", $IsoPath)
}

if ($ScriptTemplatePath) {
    $arguments += @("-ScriptTemplatePath", $ScriptTemplatePath)
}

if ($EnableNatUpdateAdapters) {
    $arguments += "-EnableNatUpdateAdapters"
}

if ($DryRun) {
    $arguments += "-DryRun"
}

& powershell @arguments
