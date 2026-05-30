param(
    [string]$Root = "C:\NIDS_Workspace",
    [switch]$Apply,
    [switch]$IncludeStaging,
    [switch]$DeleteInsteadOfMove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DirectoryStats {
    param([Parameter(Mandatory = $true)][string]$Path)
    $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue
    $fileCount = ($files | Measure-Object).Count
    $totalBytes = ($files | Measure-Object -Property Length -Sum).Sum
    if (-not $totalBytes) { $totalBytes = 0 }
    [pscustomobject]@{
        Path      = $Path
        FileCount = $fileCount
        SizeMB    = [math]::Round($totalBytes / 1MB, 2)
        SizeGB    = [math]::Round($totalBytes / 1GB, 3)
    }
}

$highConfidenceTargets = @(
    "archives\archives",
    "docs\docs",
    "reports\reports",
    "data\raw\data\raw",
    "scripts\scripts",
    "assets\screenshots\assets\screenshots"
)

$stagingTargets = @(
    "local_only",
    "found_nids",
    "merged_unique",
    "NIDS"
)

$targets = @($highConfidenceTargets)
if ($IncludeStaging) {
    $targets += $stagingTargets
}

$existing = @()
foreach ($rel in $targets) {
    $full = Join-Path $Root $rel
    if (Test-Path -LiteralPath $full) {
        $stats = Get-DirectoryStats -Path $full
        $existing += [pscustomobject]@{
            RelativePath = $rel
            FullPath     = $full
            FileCount    = $stats.FileCount
            SizeMB       = $stats.SizeMB
            SizeGB       = $stats.SizeGB
        }
    }
}

if ($existing.Count -eq 0) {
    Write-Host "No matching cleanup targets found under $Root"
    exit 0
}

$sorted = $existing | Sort-Object SizeMB -Descending
$totalMB = [math]::Round((($sorted | Measure-Object -Property SizeMB -Sum).Sum), 2)
$totalGB = [math]::Round($totalMB / 1024, 3)

Write-Host ""
Write-Host "Cleanup target preview:"
$sorted | Format-Table RelativePath, FileCount, SizeMB, SizeGB -AutoSize
Write-Host ""
Write-Host ("Estimated reclaim: {0} MB ({1} GB)" -f $totalMB, $totalGB)

if (-not $Apply) {
    Write-Host ""
    Write-Host "Dry-run only. No changes made."
    Write-Host "Run with -Apply to execute cleanup."
    Write-Host "Optional: add -IncludeStaging to include local_only/found_nids/merged_unique/NIDS."
    Write-Host "Optional: add -DeleteInsteadOfMove to permanently delete instead of moving."
    exit 0
}

if ($DeleteInsteadOfMove) {
    Write-Host ""
    Write-Host "Apply mode: permanent delete enabled."
    foreach ($item in $sorted) {
        if (Test-Path -LiteralPath $item.FullPath) {
            Remove-Item -LiteralPath $item.FullPath -Recurse -Force
            Write-Host ("Deleted: {0}" -f $item.FullPath)
        }
    }
    Write-Host "Cleanup complete."
    exit 0
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupRoot = Join-Path $Root ".cleanup_backup\$timestamp"
New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null

$logItems = @()
Write-Host ""
Write-Host ("Apply mode: moving targets to backup root: {0}" -f $backupRoot)
foreach ($item in $sorted) {
    if (-not (Test-Path -LiteralPath $item.FullPath)) {
        continue
    }
    $destPath = Join-Path $backupRoot $item.RelativePath
    $destParent = Split-Path -Path $destPath -Parent
    New-Item -Path $destParent -ItemType Directory -Force | Out-Null
    Move-Item -LiteralPath $item.FullPath -Destination $destPath -Force
    Write-Host ("Moved: {0} -> {1}" -f $item.FullPath, $destPath)
    $logItems += [pscustomobject]@{
        Timestamp    = (Get-Date).ToString("s")
        RelativePath = $item.RelativePath
        SourcePath   = $item.FullPath
        BackupPath   = $destPath
        FileCount    = $item.FileCount
        SizeMB       = $item.SizeMB
    }
}

$logDir = Join-Path $Root "docs\cleanup_logs"
New-Item -Path $logDir -ItemType Directory -Force | Out-Null
$logPath = Join-Path $logDir ("cleanup_{0}.csv" -f $timestamp)
$logItems | Export-Csv -Path $logPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host ("Cleanup complete. Backup root: {0}" -f $backupRoot)
Write-Host ("Log: {0}" -f $logPath)
