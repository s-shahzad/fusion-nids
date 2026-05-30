param(
    [ValidateSet("start", "stop", "restart", "status")]
    [string]$Action = "start",
    [string]$PythonPath = ".\.venv\Scripts\python.exe",
    [string]$BindHost = "127.0.0.1",
    [int]$DashboardPort = 8000,
    [int]$ApiPort = 8010,
    [string]$DbPath = "output\nids.db",
    [string]$StateDir = "state\local_background",
    [string]$RuntimeArgs = "",
    [switch]$StartRuntime,
    [switch]$StartApi
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$resolvedPython = if ([System.IO.Path]::IsPathRooted($PythonPath)) { $PythonPath } else { Join-Path $repoRoot $PythonPath }
$resolvedDbPath = if ([System.IO.Path]::IsPathRooted($DbPath)) { $DbPath } else { Join-Path $repoRoot $DbPath }
$resolvedStateDir = if ([System.IO.Path]::IsPathRooted($StateDir)) { $StateDir } else { Join-Path $repoRoot $StateDir }

New-Item -ItemType Directory -Force -Path $resolvedStateDir | Out-Null

$dashboardPidPath = Join-Path $resolvedStateDir "dashboard.pid"
$runtimePidPath = Join-Path $resolvedStateDir "runtime.pid"
$apiPidPath = Join-Path $resolvedStateDir "api.pid"
$dashboardStdoutPath = Join-Path $resolvedStateDir "dashboard.stdout.log"
$dashboardStderrPath = Join-Path $resolvedStateDir "dashboard.stderr.log"
$runtimeStdoutPath = Join-Path $resolvedStateDir "runtime.stdout.log"
$runtimeStderrPath = Join-Path $resolvedStateDir "runtime.stderr.log"
$apiStdoutPath = Join-Path $resolvedStateDir "api.stdout.log"
$apiStderrPath = Join-Path $resolvedStateDir "api.stderr.log"

function Get-ManagedProcess {
    param([string]$PidPath)

    if (-not (Test-Path -LiteralPath $PidPath)) {
        return $null
    }

    $rawPid = Get-Content -LiteralPath $PidPath -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $rawPid) {
        Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
        return $null
    }

    $pidValue = 0
    if (-not [int]::TryParse(($rawPid | Out-String).Trim(), [ref]$pidValue)) {
        Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
        return $null
    }

    $process = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
        return $null
    }

    return $process
}

function Stop-ManagedProcess {
    param(
        [string]$Name,
        [string]$PidPath
    )

    $process = Get-ManagedProcess -PidPath $PidPath
    if ($null -eq $process) {
        Write-Host "${Name}: not running"
        return
    }

    Stop-Process -Id $process.Id -Force
    Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
    Write-Host "${Name}: stopped pid=$($process.Id)"
}

function Start-ManagedProcess {
    param(
        [string]$Name,
        [string]$PidPath,
        [string]$StdoutPath,
        [string]$StderrPath,
        [string]$ArgumentString
    )

    $existing = Get-ManagedProcess -PidPath $PidPath
    if ($null -ne $existing) {
        Write-Host "${Name}: already running pid=$($existing.Id)"
        return
    }

    $process = Start-Process `
        -FilePath $resolvedPython `
        -ArgumentList $ArgumentString `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath `
        -WindowStyle Hidden `
        -PassThru

    Set-Content -LiteralPath $PidPath -Value $process.Id
    Write-Host "${Name}: started pid=$($process.Id) stdout=$StdoutPath stderr=$StderrPath"
}

function Show-Status {
    $dashboard = Get-ManagedProcess -PidPath $dashboardPidPath
    $runtime = Get-ManagedProcess -PidPath $runtimePidPath
    $api = Get-ManagedProcess -PidPath $apiPidPath

    if ($null -ne $dashboard) {
        Write-Host "dashboard: running pid=$($dashboard.Id) url=http://$BindHost`:$DashboardPort/healthz"
    } else {
        Write-Host "dashboard: not running"
    }

    if ($null -ne $runtime) {
        Write-Host "runtime: running pid=$($runtime.Id)"
    } else {
        Write-Host "runtime: not running"
    }

    if ($null -ne $api) {
        Write-Host "api: running pid=$($api.Id) url=http://$BindHost`:$ApiPort/health"
    } else {
        Write-Host "api: not running"
    }
}

if (-not (Test-Path -LiteralPath $resolvedPython)) {
    throw "Python executable not found: $resolvedPython"
}

switch ($Action) {
    "start" {
        if (-not (Test-Path -LiteralPath $resolvedDbPath)) {
            throw "Dashboard database not found: $resolvedDbPath"
        }

        $dashboardArgs = "-m nids dashboard --from-db `"$resolvedDbPath`" --host $BindHost --port $DashboardPort"
        Start-ManagedProcess -Name "dashboard" -PidPath $dashboardPidPath -StdoutPath $dashboardStdoutPath -StderrPath $dashboardStderrPath -ArgumentString $dashboardArgs

        if ($StartRuntime) {
            $runtimeArgsFinal = "-m nids run $RuntimeArgs".Trim()
            Start-ManagedProcess -Name "runtime" -PidPath $runtimePidPath -StdoutPath $runtimeStdoutPath -StderrPath $runtimeStderrPath -ArgumentString $runtimeArgsFinal
            if (-not $RuntimeArgs) {
                Write-Warning "Runtime started without explicit arguments. If no live interface or continuous adapter source is configured, it may exit after replay completion."
            }
        }

        if ($StartApi) {
            $apiArgs = ".\scripts\run_production_api.py"
            Start-ManagedProcess -Name "api" -PidPath $apiPidPath -StdoutPath $apiStdoutPath -StderrPath $apiStderrPath -ArgumentString $apiArgs
        }
    }
    "stop" {
        Stop-ManagedProcess -Name "api" -PidPath $apiPidPath
        Stop-ManagedProcess -Name "runtime" -PidPath $runtimePidPath
        Stop-ManagedProcess -Name "dashboard" -PidPath $dashboardPidPath
    }
    "restart" {
        Stop-ManagedProcess -Name "api" -PidPath $apiPidPath
        Stop-ManagedProcess -Name "runtime" -PidPath $runtimePidPath
        Stop-ManagedProcess -Name "dashboard" -PidPath $dashboardPidPath

        if (-not (Test-Path -LiteralPath $resolvedDbPath)) {
            throw "Dashboard database not found: $resolvedDbPath"
        }

        $dashboardArgs = "-m nids dashboard --from-db `"$resolvedDbPath`" --host $BindHost --port $DashboardPort"
        Start-ManagedProcess -Name "dashboard" -PidPath $dashboardPidPath -StdoutPath $dashboardStdoutPath -StderrPath $dashboardStderrPath -ArgumentString $dashboardArgs

        if ($StartRuntime) {
            $runtimeArgsFinal = "-m nids run $RuntimeArgs".Trim()
            Start-ManagedProcess -Name "runtime" -PidPath $runtimePidPath -StdoutPath $runtimeStdoutPath -StderrPath $runtimeStderrPath -ArgumentString $runtimeArgsFinal
        }

        if ($StartApi) {
            $apiArgs = ".\scripts\run_production_api.py"
            Start-ManagedProcess -Name "api" -PidPath $apiPidPath -StdoutPath $apiStdoutPath -StderrPath $apiStderrPath -ArgumentString $apiArgs
        }
    }
    "status" {
        Show-Status
    }
}
