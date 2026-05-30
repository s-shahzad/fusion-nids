[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "C:\NIDS_Workspace",
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$incomingRoot = Join-Path $workspaceRootResolved "NIDS_TestLab\artifacts\incoming"
$runToken = "pe-loader-static-$(Get-Date -Format yyyyMMdd-HHmmss)"
$targetDirResolved = if ($TargetDir.Trim() -ne "") {
    [System.IO.Path]::GetFullPath($TargetDir)
} else {
    Join-Path $incomingRoot $runToken
}

New-Item -ItemType Directory -Force -Path $targetDirResolved | Out-Null

@'
MZ
This is a safe inert PE-loader fixture for static analysis only.
powershell -nop -w hidden
cmd.exe /c start
http://example.invalid/dropper
ws2_32.dll
wininet.dll
urlmon.dll
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "01_invoice_viewer_update.exe") -Encoding ASCII

@'
MZ
Safe DLL fixture for static analysis only.
rundll32
regsvr32
https://example.invalid/plugin
advapi32.dll
crypt32.dll
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "02_printer_driver_patch.dll") -Encoding ASCII

@'
MZ
Safe screen saver loader fixture.
powershell
http://example.invalid/saver
wininet.dll
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "03_screen_update.scr") -Encoding ASCII

@'
This is an inert MSI-like fixture for static analysis only.
Invoke-WebRequest
certutil -urlcache -split -f
https://example.invalid/bootstrap
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "04_remote_support_patch.msi") -Encoding ASCII

@'
MZ
Safe binary blob fixture.
shellcode
http://example.invalid/payload.bin
ws2_32.dll
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "05_stage_payload.bin") -Encoding ASCII

@'
driver update notes
version 1.0.2
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "06_driver_notes.txt") -Encoding ASCII

$archiveSeedRoot = Join-Path $targetDirResolved "_loader_archive_seed"
$dropRoot = Join-Path $archiveSeedRoot "drop"
New-Item -ItemType Directory -Force -Path $dropRoot | Out-Null

@'
@echo off
powershell -nop -w hidden -c echo static fixture only
'@ | Set-Content -LiteralPath (Join-Path $dropRoot "launch.cmd") -Encoding ASCII

@'
MZ
Safe bundled loader fixture.
cmd.exe
http://example.invalid/bundle
'@ | Set-Content -LiteralPath (Join-Path $dropRoot "helper.exe") -Encoding ASCII

$zipPath = Join-Path $targetDirResolved "07_driver_bundle.zip"
Compress-Archive -Path (Join-Path $dropRoot "*") -DestinationPath $zipPath -Force
Remove-Item -LiteralPath $archiveSeedRoot -Recurse -Force

Write-Output "Staged: $targetDirResolved"
