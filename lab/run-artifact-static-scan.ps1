[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "C:\NIDS_Workspace",
    [string]$IncomingPath = "",
    [string]$ResultsRoot = "",
    [string]$RunName = "",
    [switch]$Recursive
)

$ErrorActionPreference = "Stop"

$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$python = Join-Path $workspaceRootResolved ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Python runtime not found at $python"
}
$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = if ([string]::IsNullOrWhiteSpace($previousPythonPath)) { $workspaceRootResolved } else { "$workspaceRootResolved;$previousPythonPath" }

$incomingPathResolved = if ($IncomingPath.Trim() -ne "") { [System.IO.Path]::GetFullPath($IncomingPath) } else { Join-Path $PSScriptRoot "artifacts\incoming" }
$resultsRootResolved = if ($ResultsRoot.Trim() -ne "") { [System.IO.Path]::GetFullPath($ResultsRoot) } else { Join-Path $PSScriptRoot "results" }
$runToken = if ($RunName.Trim() -ne "") { $RunName } else { "artifact-scan-$(Get-Date -Format yyyyMMdd-HHmmss)" }
$outputDir = Join-Path $resultsRootResolved $runToken
$dbPath = Join-Path $outputDir "nids.db"
$jsonlPath = Join-Path $outputDir "artifacts.jsonl"
$reportPath = Join-Path $outputDir "artifacts_report.md"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Push-Location $PSScriptRoot
try {
    $args = @(
        "-m", "nids",
        "artifact-scan",
        "--path", $incomingPathResolved,
        "--db", $dbPath,
        "--jsonl", $jsonlPath
    )
    if ($Recursive) {
        $args += "--recursive"
    }

    & $python @args
    & $python -m nids artifact-report --from-db $dbPath --out $reportPath
}
finally {
    Pop-Location
    $env:PYTHONPATH = $previousPythonPath
}

Write-Output "Results: $outputDir"
