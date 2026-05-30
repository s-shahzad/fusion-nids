[CmdletBinding()]
param(
    [string]$LabRoot = "$env:USERPROFILE\NIDS_Workspace\NIDS_TestLab",
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$DistributionName = "Ubuntu"
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

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$labRootResolved = [System.IO.Path]::GetFullPath($LabRoot)
$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)

foreach ($path in @(
    $labRootResolved,
    (Join-Path $labRootResolved "pcaps"),
    (Join-Path $labRootResolved "output"),
    (Join-Path $labRootResolved "reports"),
    (Join-Path $labRootResolved "logs")
)) {
    Ensure-Directory -Path $path
}

$restartRequired = $false
foreach ($feature in @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform")) {
    $featureState = (Get-WindowsOptionalFeature -Online -FeatureName $feature).State
    if ($featureState -ne "Enabled") {
        Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart | Out-Null
        $restartRequired = $true
    }
}

if ($restartRequired) {
    Write-Host "Enabled WSL platform features."
    Write-Host "Restart Windows, then run this script again to finish the lab install and firewall isolation."
    exit 3010
}

try {
    & wsl.exe --set-default-version 2 | Out-Null
} catch {
    Write-Warning "Unable to set the default WSL version to 2 yet. Continue after reboot if this is the first run."
}

$installedDistributions = @()
try {
    $installedDistributions = (& wsl.exe -l -q 2>$null) | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
} catch {
    $installedDistributions = @()
}

if ($installedDistributions -notcontains $DistributionName) {
    Write-Host "Installing WSL distribution '$DistributionName'."
    Write-Host "When prompted, complete the Linux first-run setup, then rerun this script to apply host isolation."
    & wsl.exe --install -d $DistributionName
    exit $LASTEXITCODE
}

& wsl.exe -d $DistributionName -- bash -lc "printf ready" | Out-Null
Start-Sleep -Seconds 4

$wslAdapter = Get-NetIPAddress -InterfaceAlias "vEthernet (WSL)" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -and $_.IPAddress -notlike "169.254*" } |
    Select-Object -First 1

$ruleName = "NIDS Test Lab - Block WSL Inbound To Host"
$existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existingRule) {
    $existingRule | Remove-NetFirewallRule
}

$remoteAddress = "172.16.0.0/12"
if ($wslAdapter) {
    $remoteAddress = "$($wslAdapter.IPAddress)/$($wslAdapter.PrefixLength)"
}

New-NetFirewallRule `
    -DisplayName $ruleName `
    -Direction Inbound `
    -Action Block `
    -RemoteAddress $remoteAddress `
    -Profile Any `
    -Description "Block inbound traffic from the WSL test lab to the Windows host." | Out-Null

Write-Host "Isolated test lab prepared."
Write-Host "Workspace root: $workspaceRootResolved"
Write-Host "Lab root: $labRootResolved"
Write-Host "Blocked remote range: $remoteAddress"
Write-Host "Use C:\NIDS_Workspace\NIDS_TestLab\RUN_OFFLINE_TEST.ps1 for offline replay inside the lab folder."
