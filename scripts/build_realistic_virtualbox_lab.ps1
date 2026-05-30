[CmdletBinding()]
param(
    [string]$LabRoot = "$env:USERPROFILE\NIDS_Workspace\NIDS_TestLab",
    [string]$InternalNetworkName = "nidslab",
    [string]$AttackerSourceVm = "kali",
    [string]$AttackerCloneName = "nids-kali-attacker",
    [string]$TargetVmName = "nids-ubuntu-target",
    [string]$SensorVmName = "nids-ubuntu-sensor",
    [string]$UbuntuIsoPath = "",
    [switch]$DownloadUbuntuIso,
    [switch]$AttachIso,
    [switch]$SkipNatUpdateAdapters
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
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
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$IgnoreFailure,
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

    if ($process.ExitCode -ne 0 -and -not $IgnoreFailure) {
        $details = @($stderr.Trim(), $stdout.Trim()) | Where-Object { $_ }
        throw "VBoxManage failed: $($Arguments -join ' ')`n$($details -join [Environment]::NewLine)"
    }

    if ($CaptureOutput) {
        return @($stdout -split "\r?\n" | Where-Object { $_ -ne "" })
    }
}

function Get-RegisteredVmNames {
    param([Parameter(Mandatory = $true)][string]$VBoxManage)

    $names = @()
    foreach ($line in (Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @("list", "vms") -CaptureOutput)) {
        if ($line -match '^"(.+)"\s+\{') {
            $names += $matches[1]
        }
    }
    return $names
}

function Test-VMExists {
    param(
        [Parameter(Mandatory = $true)][string[]]$RegisteredVmNames,
        [Parameter(Mandatory = $true)][string]$VMName
    )

    return $RegisteredVmNames -contains $VMName
}

function Download-UbuntuIso {
    param(
        [Parameter(Mandatory = $true)][string]$IsoPath,
        [Parameter(Mandatory = $true)][string]$SourceUrl
    )

    if (Test-Path $IsoPath) {
        return
    }

    $bits = Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue
    if ($bits) {
        Start-BitsTransfer -Source $SourceUrl -Destination $IsoPath -DisplayName "Ubuntu Server ISO"
        return
    }

    Invoke-WebRequest -Uri $SourceUrl -OutFile $IsoPath
}

function Ensure-AttackerClone {
    param(
        [Parameter(Mandatory = $true)][string]$VBoxManage,
        [Parameter(Mandatory = $true)][string[]]$RegisteredVmNames,
        [Parameter(Mandatory = $true)][string]$SourceVm,
        [Parameter(Mandatory = $true)][string]$CloneVm,
        [Parameter(Mandatory = $true)][string]$VmBaseFolder,
        [Parameter(Mandatory = $true)][string]$InternalNetworkName
    )

    if (-not (Test-VMExists -RegisteredVmNames $RegisteredVmNames -VMName $SourceVm)) {
        throw "Source VM '$SourceVm' was not found. Adjust -AttackerSourceVm or import a Kali VM first."
    }

    if (-not (Test-VMExists -RegisteredVmNames $RegisteredVmNames -VMName $CloneVm)) {
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "clonevm", $SourceVm,
            "--name", $CloneVm,
            "--basefolder", $VmBaseFolder,
            "--register",
            "--mode", "machine"
        )
    }

    Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
        "modifyvm", $CloneVm,
        "--nic1", "intnet",
        "--intnet1", $InternalNetworkName,
        "--nictype1", "virtio",
        "--nicpromisc1", "deny",
        "--nat-localhostreachable1", "off",
        "--nic2", "none",
        "--nic3", "none",
        "--nic4", "none",
        "--audio-enabled", "off",
        "--usb", "off",
        "--clipboard-mode", "disabled",
        "--draganddrop", "disabled",
        "--vrde", "off"
    )

    Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @("modifyvm", $CloneVm, "--natpf1", "delete", "ssh") -IgnoreFailure
}

function Ensure-UbuntuLabVm {
    param(
        [Parameter(Mandatory = $true)][string]$VBoxManage,
        [Parameter(Mandatory = $true)][string[]]$RegisteredVmNames,
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $true)][string]$VmBaseFolder,
        [Parameter(Mandatory = $true)][string]$InternalNetworkName,
        [Parameter(Mandatory = $true)][int]$MemoryMB,
        [Parameter(Mandatory = $true)][int]$CPUs,
        [Parameter(Mandatory = $true)][int]$DiskGB,
        [Parameter(Mandatory = $true)][bool]$AllowPromiscuousCapture,
        [Parameter(Mandatory = $true)][bool]$CreateNatUpdateAdapter,
        [string]$IsoPath
    )

    $vmRoot = Join-Path $VmBaseFolder $VMName
    $diskPath = Join-Path $vmRoot "$VMName.vdi"
    $safeDiskMB = [Math]::Max(30000, $DiskGB * 1024)

    Ensure-Directory -Path $vmRoot

    if (-not (Test-VMExists -RegisteredVmNames $RegisteredVmNames -VMName $VMName)) {
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "createvm", "--name", $VMName, "--ostype", "Ubuntu_64", "--basefolder", $VmBaseFolder, "--register"
        )

        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "storagectl", $VMName, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"
        )
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "storagectl", $VMName, "--name", "IDE", "--add", "ide"
        )
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "createmedium", "disk", "--filename", $diskPath, "--size", "$safeDiskMB"
        )
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "storageattach", $VMName, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", $diskPath
        )
    }

    Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
        "modifyvm", $VMName,
        "--memory", "$MemoryMB",
        "--cpus", "$CPUs",
        "--vram", "32",
        "--graphicscontroller", "vmsvga",
        "--boot1", "dvd",
        "--boot2", "disk",
        "--boot3", "none",
        "--boot4", "none",
        "--audio-enabled", "off",
        "--usb", "off",
        "--clipboard-mode", "disabled",
        "--draganddrop", "disabled",
        "--nic1", "intnet",
        "--intnet1", $InternalNetworkName,
        "--nictype1", "virtio",
        "--nicpromisc1", $(if ($AllowPromiscuousCapture) { "allow-all" } else { "deny" }),
        "--cableconnected1", "on",
        "--nat-localhostreachable1", "off",
        "--vrde", "off"
    )

    if ($CreateNatUpdateAdapter) {
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "modifyvm", $VMName,
            "--nic2", "nat",
            "--nictype2", "virtio",
            "--cableconnected2", "on",
            "--nat-localhostreachable2", "off"
        )
    } else {
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @("modifyvm", $VMName, "--nic2", "none")
    }

    if ($IsoPath) {
        Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @(
            "storageattach", $VMName, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "dvddrive", "--medium", $IsoPath
        )
    }
}

$labRootResolved = [System.IO.Path]::GetFullPath($LabRoot)
$vmBaseFolder = Join-Path $labRootResolved "vms"
$isoFolder = Join-Path $labRootResolved "isos"
$summaryPath = Join-Path $labRootResolved "realistic_lab_summary.json"

foreach ($path in @(
    $labRootResolved,
    $vmBaseFolder,
    $isoFolder,
    (Join-Path $labRootResolved "reports"),
    (Join-Path $labRootResolved "logs")
)) {
    Ensure-Directory -Path $path
}

if (-not $UbuntuIsoPath) {
    $UbuntuIsoPath = Join-Path $isoFolder "ubuntu-24.04.4-live-server-amd64.iso"
}

$ubuntuIsoResolved = [System.IO.Path]::GetFullPath($UbuntuIsoPath)
$ubuntuIsoUrl = "https://releases.ubuntu.com/noble/ubuntu-24.04.4-live-server-amd64.iso"

if ($DownloadUbuntuIso) {
    Download-UbuntuIso -IsoPath $ubuntuIsoResolved -SourceUrl $ubuntuIsoUrl
    $AttachIso = $true
}

$vbox = Get-VBoxManagePath
$registeredVmNames = Get-RegisteredVmNames -VBoxManage $vbox

Ensure-AttackerClone -VBoxManage $vbox -RegisteredVmNames $registeredVmNames -SourceVm $AttackerSourceVm -CloneVm $AttackerCloneName -VmBaseFolder $vmBaseFolder -InternalNetworkName $InternalNetworkName

$registeredVmNames = Get-RegisteredVmNames -VBoxManage $vbox
$resolvedIsoForAttach = ""
if ($AttachIso -and (Test-Path $ubuntuIsoResolved)) {
    $resolvedIsoForAttach = $ubuntuIsoResolved
}

Ensure-UbuntuLabVm -VBoxManage $vbox -RegisteredVmNames $registeredVmNames -VMName $TargetVmName -VmBaseFolder $vmBaseFolder -InternalNetworkName $InternalNetworkName -MemoryMB 4096 -CPUs 2 -DiskGB 40 -AllowPromiscuousCapture:$false -CreateNatUpdateAdapter:(-not $SkipNatUpdateAdapters) -IsoPath $resolvedIsoForAttach
$registeredVmNames = Get-RegisteredVmNames -VBoxManage $vbox
Ensure-UbuntuLabVm -VBoxManage $vbox -RegisteredVmNames $registeredVmNames -VMName $SensorVmName -VmBaseFolder $vmBaseFolder -InternalNetworkName $InternalNetworkName -MemoryMB 6144 -CPUs 4 -DiskGB 60 -AllowPromiscuousCapture:$true -CreateNatUpdateAdapter:(-not $SkipNatUpdateAdapters) -IsoPath $resolvedIsoForAttach

$summary = [ordered]@{
    lab_root = $labRootResolved
    realistic_lab = [ordered]@{
        network = [ordered]@{
            mode = "VirtualBox Internal Network"
            name = $InternalNetworkName
            host_visible = $false
        }
        attacker = [ordered]@{
            source_vm = $AttackerSourceVm
            lab_vm = $AttackerCloneName
            role = "Traffic generator / attacker"
            adapters = @(
                "Adapter 1: Internal Network ($InternalNetworkName)"
            )
        }
        target = [ordered]@{
            vm = $TargetVmName
            role = "Victim / service host"
            adapters = @(
                "Adapter 1: Internal Network ($InternalNetworkName)",
                $(if ($SkipNatUpdateAdapters) { "Adapter 2: none" } else { "Adapter 2: NAT for package updates only" })
            )
        }
        sensor = [ordered]@{
            vm = $SensorVmName
            role = "NIDS sensor / packet capture node"
            adapters = @(
                "Adapter 1: Internal Network ($InternalNetworkName), promiscuous allow-all",
                $(if ($SkipNatUpdateAdapters) { "Adapter 2: none" } else { "Adapter 2: NAT for package updates only" })
            )
        }
    }
    ubuntu_iso = [ordered]@{
        path = $ubuntuIsoResolved
        exists = (Test-Path $ubuntuIsoResolved)
        attached_to_ubuntu_vms = ($resolvedIsoForAttach -ne "")
        official_download = $ubuntuIsoUrl
    }
    security_posture = @(
        "No Host-Only adapters configured",
        "No Bridged adapters configured",
        "Clipboard disabled on lab VMs",
        "Drag and drop disabled on lab VMs",
        "VRDE disabled on lab VMs"
    )
    next_steps = @(
        "Install Ubuntu Server on $TargetVmName and $SensorVmName if the ISO is attached.",
        "Assign static internal IPs such as 10.77.0.10 (attacker), 10.77.0.20 (target), 10.77.0.30 (sensor).",
        "Run the NIDS stack inside $SensorVmName or replay PCAPs from the host against captures exported from the sensor."
    )
}

$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8

Write-Host "Realistic VirtualBox lab prepared."
Write-Host "Summary: $summaryPath"
Write-Host "Attacker clone: $AttackerCloneName"
Write-Host "Target VM: $TargetVmName"
Write-Host "Sensor VM: $SensorVmName"
if ($resolvedIsoForAttach) {
    Write-Host "Ubuntu ISO attached: $resolvedIsoForAttach"
} else {
    Write-Host "Ubuntu ISO not attached yet. Use -AttachIso after placing the ISO at $ubuntuIsoResolved"
}
