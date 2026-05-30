[CmdletBinding()]
param(
    [string]$RepoDir = "",
    [string]$OutDir = "",
    [string]$BundleName = "",
    [switch]$VerifyOnly,
    [switch]$Help
)

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "oracle_common.ps1")

if ($Help) {
    @"
Usage:
  powershell -ExecutionPolicy Bypass -File scripts/oracle_prepare_bundle.ps1 [-RepoDir <path>] [-OutDir <path>] [-BundleName <name>] [-VerifyOnly]
"@ | Write-Host
    exit 0
}

if ([string]::IsNullOrWhiteSpace($RepoDir)) {
    $RepoDir = Get-OracleRepoRoot
}

Assert-OracleDirectory $RepoDir
Test-OracleDeploymentInputs -RepoDir $RepoDir

if ($VerifyOnly) {
    Write-OracleLog "verified_repo_dir=$RepoDir"
    Write-OracleLog "verified_inputs=ok"
    exit 0
}

$bundle = New-OracleDeploymentBundle -RepoDir $RepoDir -OutDir $OutDir -BundleName $BundleName
Write-OracleLog "bundle_path=$($bundle.BundlePath)"
Write-OracleLog "manifest_path=$($bundle.ManifestPath)"
Write-OracleLog "bundle_sha256=$($bundle.BundleSha256)"
