[CmdletBinding()]
param(
    [string]$LabRoot = "$env:USERPROFILE\NIDS_Workspace\NIDS_TestLab",
    [string]$IsoPath = "",
    [string]$ScriptTemplatePath = "",
    [string]$UserName = "",
    [string]$UserPassword = "",
    [string]$FullUserName = "NIDS Lab",
    [string]$TargetVmName = "nids-ubuntu-target",
    [string]$SensorVmName = "nids-ubuntu-sensor",
    [switch]$EnableNatUpdateAdapters,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

if (-not $UserName) {
    $UserName = $env:LAB_VM_USER
}
if (-not $UserPassword) {
    $UserPassword = $env:LAB_VM_PASS
}
if (-not $UserName) {
    throw "Missing lab VM username. Set LAB_VM_USER or pass -UserName."
}
if (-not $UserPassword) {
    throw "Missing lab VM password. Set LAB_VM_PASS or pass -UserPassword."
}

function Get-VBoxManagePath {
    $candidates = @(@(
        (Join-Path ${env:ProgramFiles} "Oracle\VirtualBox\VBoxManage.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Oracle\VirtualBox\VBoxManage.exe")
    ) | Where-Object { $_ -and (Test-Path $_) })

    if ($candidates.Count -gt 0) {
        return [string]($candidates[0])
    }

    $command = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if ($command) {
        return [string]($command.Source)
    }

    throw "VBoxManage.exe not found. Install VirtualBox first."
}

function Invoke-VBoxManage {
    param(
        [Parameter(Mandatory = $true)][string]$VBoxManage,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $quotedArguments = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '\"') + '"'
        } else {
            $argument
        }
    }

    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName = $VBoxManage
    $processInfo.Arguments = [string]::Join(' ', $quotedArguments)
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::Start($processInfo)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        $details = @($stderr.Trim(), $stdout.Trim()) | Where-Object { $_ }
        throw "VBoxManage failed: $($Arguments -join ' ')`n$($details -join [Environment]::NewLine)"
    }

    if ($stdout.Trim()) {
        Write-Output $stdout.TrimEnd()
    }
}

function Set-NatAdapterState {
    param(
        [Parameter(Mandatory = $true)][string]$VBoxManage,
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $true)][bool]$Enabled
    )

    if ($Enabled) {
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "modifyvm", $VMName,
            "--nic2", "nat",
            "--nictype2", "virtio",
            "--cableconnected2", "on",
            "--nat-localhostreachable2", "off"
        ) | Out-Null
    } else {
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @("modifyvm", $VMName, "--nic2", "none") | Out-Null
    }
}

function Start-UnattendedInstall {
    param(
        [Parameter(Mandatory = $true)][string]$VBoxManage,
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $true)][string]$IsoPath,
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$UserPassword,
        [Parameter(Mandatory = $true)][string]$FullUserName,
        [Parameter(Mandatory = $true)][string]$HostName,
        [string]$ScriptTemplatePath,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    $startVmMode = if ($DryRun) { "none" } else { "headless" }

    $arguments = @(
        "unattended", "install", $VMName,
        "--iso=$IsoPath",
        "--user=$UserName",
        "--user-password=$UserPassword",
        "--full-user-name=$FullUserName",
        "--hostname=$HostName",
        "--locale=en_US",
        "--country=US",
        "--time-zone=America/New_York",
        "--package-selection-adjustment=minimal",
        "--no-install-additions",
        "--start-vm=$startVmMode"
    )

    if ($ScriptTemplatePath) {
        $arguments += "--script-template=$ScriptTemplatePath"
    }

    if ($DryRun) {
        $arguments += "--dry-run"
    }

    Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments $arguments
}

$labRootResolved = [System.IO.Path]::GetFullPath($LabRoot)
if (-not $IsoPath) {
    $IsoPath = Join-Path $labRootResolved "isos\ubuntu-24.04.4-live-server-amd64.iso"
}
if (-not $ScriptTemplatePath) {
    $ScriptTemplatePath = Join-Path $labRootResolved "templates\ubuntu_autoinstall_nids_user_data"
}

$isoResolved = [System.IO.Path]::GetFullPath($IsoPath)
if (-not (Test-Path $isoResolved)) {
    throw "Ubuntu ISO not found: $isoResolved"
}
$scriptTemplateResolved = [System.IO.Path]::GetFullPath($ScriptTemplatePath)
if (-not (Test-Path $scriptTemplateResolved)) {
    throw "Autoinstall template not found: $scriptTemplateResolved"
}

$vbox = Get-VBoxManagePath

Set-NatAdapterState -VBoxManage $vbox -VMName $TargetVmName -Enabled:$EnableNatUpdateAdapters
Set-NatAdapterState -VBoxManage $vbox -VMName $SensorVmName -Enabled:$EnableNatUpdateAdapters

Start-UnattendedInstall -VBoxManage $vbox -VMName $TargetVmName -IsoPath $isoResolved -UserName $UserName -UserPassword $UserPassword -FullUserName $FullUserName -HostName "nids-ubuntu-target.nidslab" -ScriptTemplatePath $scriptTemplateResolved -DryRun:$DryRun
Start-UnattendedInstall -VBoxManage $vbox -VMName $SensorVmName -IsoPath $isoResolved -UserName $UserName -UserPassword $UserPassword -FullUserName $FullUserName -HostName "nids-ubuntu-sensor.nidslab" -ScriptTemplatePath $scriptTemplateResolved -DryRun:$DryRun

$statusPath = Join-Path $labRootResolved "guest_install_status.json"
$status = [ordered]@{
    lab_root = $labRootResolved
    iso_path = $isoResolved
    script_template_path = $scriptTemplateResolved
    nat_update_adapters = [bool]$EnableNatUpdateAdapters
    dry_run = [bool]$DryRun
    credentials = [ordered]@{
        username = $UserName
        password = "<redacted>"
        password_source = "LAB_VM_PASS or -UserPassword"
    }
    guests = @(
        [ordered]@{ name = $TargetVmName; hostname = "nids-ubuntu-target.nidslab" },
        [ordered]@{ name = $SensorVmName; hostname = "nids-ubuntu-sensor.nidslab" }
    )
}

$status | ConvertTo-Json -Depth 4 | Set-Content -Path $statusPath -Encoding UTF8

Write-Host "Guest install workflow prepared."
Write-Host "Status: $statusPath"
