param(
    [Alias("Host")]
    [string]$DashboardHost = "127.0.0.1",
    [Alias("Port")]
    [int]$DashboardPort = 8000,
    [string]$Token = ""
)

$query = ""
if ($Token -ne "") {
    $query = "?token=$Token"
}

$healthUrl = "http://$DashboardHost`:$DashboardPort/healthz$query"
$readyUrl = "http://$DashboardHost`:$DashboardPort/readyz$query"

try {
    $health = Invoke-RestMethod -Method Get -Uri $healthUrl -TimeoutSec 5
    $ready = Invoke-RestMethod -Method Get -Uri $readyUrl -TimeoutSec 5

    Write-Host "healthz: $($health.status) db_exists=$($health.db_exists)"
    Write-Host "readyz:  $($ready.status) missing_tables=$($ready.missing_tables -join ',')"

    if ($health.status -ne "ok") { exit 1 }
    if ($ready.status -eq "not_ready") { exit 2 }

    exit 0
}
catch {
    Write-Error "Health check failed: $($_.Exception.Message)"
    exit 3
}
