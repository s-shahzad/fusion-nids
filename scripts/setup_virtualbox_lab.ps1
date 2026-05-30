[CmdletBinding()]
param(
    [string]$LabRoot = "$env:USERPROFILE\NIDS_Workspace\NIDS_TestLab",
    [switch]$InstallVirtualBox
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

$labRootResolved = [System.IO.Path]::GetFullPath($LabRoot)
foreach ($path in @(
    $labRootResolved,
    (Join-Path $labRootResolved "isos"),
    (Join-Path $labRootResolved "vm_exports"),
    (Join-Path $labRootResolved "pcaps"),
    (Join-Path $labRootResolved "reports"),
    (Join-Path $labRootResolved "logs")
)) {
    Ensure-Directory -Path $path
}

$winget = Get-Command winget.exe -ErrorAction SilentlyContinue
if (-not $winget) {
    throw "winget is not available on this system."
}

$virtualBoxInstalled = $false
$virtualBoxPath = Join-Path ${env:ProgramFiles} "Oracle\VirtualBox\VBoxManage.exe"
if (Test-Path $virtualBoxPath) {
    $virtualBoxInstalled = $true
}

if (-not $virtualBoxInstalled -and $InstallVirtualBox) {
    if (-not (Test-IsAdministrator)) {
        throw "InstallVirtualBox requires an elevated PowerShell session."
    }

    & winget install --id Oracle.VirtualBox --exact --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "VirtualBox installation failed with exit code $LASTEXITCODE."
    }
    $virtualBoxInstalled = Test-Path $virtualBoxPath
}

$summary = [ordered]@{
    lab_root = $labRootResolved
    virtualbox_installed = $virtualBoxInstalled
    vboxmanage_path = if ($virtualBoxInstalled) { $virtualBoxPath } else { "" }
    recommended_network_mode = "NAT for a single guest, Internal Network for multi-VM traffic generation"
    host_protection = "Do not attach Host-Only Adapter unless you intentionally need host-guest networking"
}

$summaryPath = Join-Path $labRootResolved "virtualbox_lab_summary.json"
$summary | ConvertTo-Json -Depth 3 | Set-Content -Path $summaryPath -Encoding UTF8

Write-Host "VirtualBox lab scaffold prepared."
Write-Host "Lab root: $labRootResolved"
Write-Host "Summary: $summaryPath"
if (-not $virtualBoxInstalled) {
    Write-Host "VirtualBox is not installed yet."
    Write-Host "Run this script as Administrator with -InstallVirtualBox to install it."
}
