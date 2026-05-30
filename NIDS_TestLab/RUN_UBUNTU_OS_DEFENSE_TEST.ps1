param(
    [ValidateSet("cron-http", "systemd-dns", "defense-tamper", "staged-http-exfil")]
    [string]$Case = "cron-http",
    [string]$RunName = ""
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonExe = Join-Path $repoRoot ".venv\Scripts\python.exe"
$scriptPath = Join-Path $repoRoot "scripts\ubuntu_os_defense_validation.py"

if (-not (Test-Path $pythonExe)) {
    throw "Python venv not found at $pythonExe"
}

if (-not $RunName) {
    $prefix = if ($Case -eq "systemd-dns") {
        "ubuntu-os-systemd-dns-beacon"
    } elseif ($Case -eq "defense-tamper") {
        "ubuntu-os-defense-tamper"
    } elseif ($Case -eq "staged-http-exfil") {
        "ubuntu-os-staged-http-exfil"
    } else {
        "ubuntu-os-cron-http-beacon"
    }
    $RunName = $prefix + "-" + (Get-Date -Format "yyyyMMdd-HHmmss")
}

& $pythonExe $scriptPath --case $Case --run-name $RunName
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
