[CmdletBinding()]
param(
    [string]$IsoPath = "",
    [switch]$InternalNetwork
)

$ErrorActionPreference = "Stop"

$workspaceRoot = "C:\NIDS_Workspace"
$scriptPath = Join-Path $workspaceRoot "scripts\create_virtualbox_lab_vm.ps1"

if (-not (Test-Path $scriptPath)) {
    throw "VM creation script not found: $scriptPath"
}

powershell -ExecutionPolicy Bypass -File $scriptPath `
    -VMName "nids-ubuntu-lab" `
    -LabRoot $PSScriptRoot `
    -IsoPath $IsoPath `
    -MemoryMB 8192 `
    -CPUs 4 `
    -DiskGB 60 `
    -InternalNetwork:$InternalNetwork
