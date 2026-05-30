[CmdletBinding()]
param(
    [string]$VMName = "nids-ubuntu-lab",
    [string]$LabRoot = "$env:USERPROFILE\NIDS_Workspace\NIDS_TestLab",
    [string]$IsoPath = "",
    [int]$MemoryMB = 8192,
    [int]$CPUs = 4,
    [int]$DiskGB = 60,
    [switch]$InternalNetwork,
    [string]$InternalNetworkName = "nidslab"
)

$ErrorActionPreference = "Stop"

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
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$CaptureOutput
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

    if ($CaptureOutput) {
        return @($stdout -split "\r?\n" | Where-Object { $_ -ne "" })
    }
}

$labRootResolved = [System.IO.Path]::GetFullPath($LabRoot)
$vmBaseFolder = Join-Path $labRootResolved "vms"
$vmRoot = Join-Path $labRootResolved "vms\$VMName"
$diskPath = Join-Path $vmRoot "$VMName.vdi"
$logsPath = Join-Path $labRootResolved "logs"

New-Item -ItemType Directory -Force -Path $vmBaseFolder, $vmRoot, $logsPath | Out-Null

$vbox = Get-VBoxManagePath

$existingVms = Invoke-VBoxManage -VBoxManage $vbox -Arguments @("list", "vms") -CaptureOutput
if ($existingVms -match ('"' + [Regex]::Escape($VMName) + '"')) {
    throw "Virtual machine '$VMName' already exists."
}

$safeMemory = [Math]::Max(4096, [Math]::Min(12288, $MemoryMB))
$safeCPUs = [Math]::Max(2, [Math]::Min(6, $CPUs))
$safeDiskMB = [Math]::Max(30000, $DiskGB * 1024)

Invoke-VBoxManage -VBoxManage $vbox -Arguments @("createvm", "--name", $VMName, "--ostype", "Ubuntu_64", "--basefolder", $vmBaseFolder, "--register")
Invoke-VBoxManage -VBoxManage $vbox -Arguments @(
    "modifyvm", $VMName,
    "--memory", "$safeMemory",
    "--cpus", "$safeCPUs",
    "--vram", "32",
    "--boot1", "dvd",
    "--boot2", "disk",
    "--boot3", "none",
    "--boot4", "none",
    "--graphicscontroller", "vmsvga",
    "--audio-enabled", "off",
    "--usb", "off",
    "--clipboard-mode", "disabled",
    "--draganddrop", "disabled",
    "--nictype1", "virtio",
    "--cableconnected1", "on",
    "--nicpromisc1", "deny",
    "--nat-localhostreachable1", "off"
)

if ($InternalNetwork) {
    Invoke-VBoxManage -VBoxManage $vbox -Arguments @(
        "modifyvm", $VMName,
        "--nic1", "intnet",
        "--intnet1", $InternalNetworkName
    )
} else {
    Invoke-VBoxManage -VBoxManage $vbox -Arguments @("modifyvm", $VMName, "--nic1", "nat")
}

Invoke-VBoxManage -VBoxManage $vbox -Arguments @("createmedium", "disk", "--filename", $diskPath, "--size", "$safeDiskMB")
Invoke-VBoxManage -VBoxManage $vbox -Arguments @("storagectl", $VMName, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci")
Invoke-VBoxManage -VBoxManage $vbox -Arguments @("storageattach", $VMName, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", $diskPath)
Invoke-VBoxManage -VBoxManage $vbox -Arguments @("storagectl", $VMName, "--name", "IDE", "--add", "ide")

if ($IsoPath.Trim() -ne "") {
    $isoResolved = [System.IO.Path]::GetFullPath($IsoPath)
    if (-not (Test-Path $isoResolved)) {
        throw "ISO not found: $isoResolved"
    }
    Invoke-VBoxManage -VBoxManage $vbox -Arguments @("storageattach", $VMName, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "dvddrive", "--medium", $isoResolved)
}

$summary = [ordered]@{
    vm_name = $VMName
    vm_directory = $vmRoot
    disk_path = $diskPath
    iso_attached = ($IsoPath.Trim() -ne "")
    memory_mb = $safeMemory
    cpus = $safeCPUs
    disk_gb = [Math]::Round($safeDiskMB / 1024.0, 2)
    network_mode = if ($InternalNetwork) { "Internal Network ($InternalNetworkName)" } else { "NAT" }
    clipboard = "disabled"
    drag_and_drop = "disabled"
    host_only_adapter = "not configured"
}

$summaryPath = Join-Path $vmRoot "vm_summary.json"
$summary | ConvertTo-Json -Depth 3 | Set-Content -Path $summaryPath -Encoding UTF8

Write-Host "Created VM '$VMName'."
Write-Host "Summary: $summaryPath"
if ($IsoPath.Trim() -eq "") {
    Write-Host "No ISO attached yet. Attach an Ubuntu ISO before first boot."
}
Write-Host "Safe mode: $($summary.network_mode)"
