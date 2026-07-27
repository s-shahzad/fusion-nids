[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "C:\NIDS_Workspace",
    [string]$PcapPath = "",
    [string]$LabelsPath = "",
    [string]$ConfigPath = "",
    [string]$ResultsRoot = "",
    [string]$RunName = "",
    [int]$ThresholdLookbackDays = 3650,
    [switch]$EnableUnsupervised
)

$ErrorActionPreference = "Stop"

$workspaceRootResolved = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$python = Join-Path $workspaceRootResolved ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Python runtime not found at $python"
}
$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = if ([string]::IsNullOrWhiteSpace($previousPythonPath)) { $workspaceRootResolved } else { "$workspaceRootResolved;$previousPythonPath" }

$pcapDir = if ($PcapPath.Trim() -ne "") { [System.IO.Path]::GetFullPath($PcapPath) } else { Join-Path $PSScriptRoot "pcaps" }
$configPathResolved = if ($ConfigPath.Trim() -ne "") { [System.IO.Path]::GetFullPath($ConfigPath) } else { Join-Path $PSScriptRoot "config\offline_replay_profile.yml" }
$resultsRootResolved = if ($ResultsRoot.Trim() -ne "") { [System.IO.Path]::GetFullPath($ResultsRoot) } else { Join-Path $PSScriptRoot "results" }
$runToken = if ($RunName.Trim() -ne "") { $RunName } else { "offline-$(Get-Date -Format yyyyMMdd-HHmmss)" }
$outputDir = Join-Path $resultsRootResolved $runToken
$modelPath = Join-Path $workspaceRootResolved "models\model.pkl"
$rulesPath = Join-Path $workspaceRootResolved "rules\rules.yml"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

$args = @(
    "-m", "nids",
    "run",
    "--pcap-dir", $pcapDir,
    "--output-dir", $outputDir,
    "--config", $configPathResolved,
    "--model", $modelPath,
    "--rules", $rulesPath
)

if ($EnableUnsupervised) {
    $args += "--unsupervised"
}

if ($LabelsPath.Trim() -ne "") {
    $args += @("--labels", $LabelsPath)
}

try {
    & $python @args

    $dbPath = Join-Path $outputDir "nids.db"
    if (Test-Path $dbPath) {
        & $python -m nids report --from-db $dbPath --out (Join-Path $outputDir "serious_test_report.md")
        & $python -m nids threshold-report --from-db $dbPath --out-json (Join-Path $outputDir "threshold_tuning.json") --out-md (Join-Path $outputDir "threshold_tuning.md") --lookback-days $ThresholdLookbackDays
    }
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
Write-Output "Results: $outputDir"
