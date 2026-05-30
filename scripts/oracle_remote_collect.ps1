[CmdletBinding()]
param(
    [string]$EnvFile = "",
    [string]$RemoteHost = "",
    [string]$User = "",
    [string]$KeyPath = "",
    [int]$SshPort = 0,
    [string]$ProjectDir = "",
    [string]$OutDir = "",
    [int]$Tail = 100,
    [switch]$IncludeOutput,
    [switch]$Archive,
    [switch]$Help
)

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "oracle_common.ps1")

if ($Help) {
    @"
Usage:
  powershell -ExecutionPolicy Bypass -File scripts/oracle_remote_collect.ps1 [-EnvFile <path>] [-RemoteHost <ip>] [-User <user>] [-KeyPath <path>] [-SshPort <port>] [-ProjectDir <path>] [-OutDir <path>] [-Tail <lines>] [-IncludeOutput] [-Archive]
"@ | Write-Host
    exit 0
}

$resolvedEnvFile = Get-OracleOptionalEnvFile -EnvFile $EnvFile
$settings = Import-OracleProjectEnv -EnvFile $resolvedEnvFile
$context = New-OracleSshContext -Settings $settings -RemoteHost $RemoteHost -RemoteUser $User -SshKeyPath $KeyPath -SshPort $SshPort -RemoteProjectDir $ProjectDir -RemoteUploadDir ""

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Get-OracleSetting -Settings $settings -Key "ORACLE_VM_COLLECTION_DIR"
    if ([string]::IsNullOrWhiteSpace($OutDir)) {
        $OutDir = Join-Path (Get-OracleRepoRoot) "archives\oracle_vm_collections"
    }
}

$stamp = Get-OracleTimestampUtc
$destinationDir = Join-Path $OutDir $stamp
New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null

$psRemote = @'
set -euo pipefail
project_dir="$1"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"
if sudo docker compose version >/dev/null 2>&1; then
  compose_base=(sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
else
  compose_base=(sudo docker-compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
fi
"${compose_base[@]}" ps -a || true
'@
$psOutput = Invoke-OracleRemoteScript -Context $context -ScriptBody $psRemote -Arguments @($context.RemoteProjectDir) -CaptureOutput -AllowFailure
Set-Content -Path (Join-Path $destinationDir "docker-compose-ps.txt") -Value $psOutput.Output -Encoding UTF8

$logsRemote = @'
set -euo pipefail
project_dir="$1"
tail_lines="$2"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"
if sudo docker compose version >/dev/null 2>&1; then
  compose_base=(sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
else
  compose_base=(sudo docker-compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
fi
"${compose_base[@]}" logs --tail "$tail_lines" nids-runtime || true
'@
$logsOutput = Invoke-OracleRemoteScript -Context $context -ScriptBody $logsRemote -Arguments @($context.RemoteProjectDir, ([string]$Tail)) -CaptureOutput -AllowFailure
Set-Content -Path (Join-Path $destinationDir "docker-compose-runtime-tail.txt") -Value $logsOutput.Output -Encoding UTF8

$runtimeDir = Join-Path $destinationDir "runtime"
$manifestsDir = Join-Path $destinationDir "manifests"
New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
New-Item -ItemType Directory -Path $manifestsDir -Force | Out-Null

Invoke-OracleScp -Context $context -Arguments @("-r", "$($context.RemoteTarget):$($context.RemoteCloudDataDir)/runtime/logs", $runtimeDir)
Invoke-OracleScp -Context $context -Arguments @("-r", "$($context.RemoteTarget):$($context.RemoteCloudDataDir)/runtime/reports", $runtimeDir)
Invoke-OracleScp -Context $context -Arguments @("-r", "$($context.RemoteTarget):$($context.RemoteCloudDataDir)/manifests", $destinationDir)

if ($IncludeOutput) {
    Invoke-OracleScp -Context $context -Arguments @("-r", "$($context.RemoteTarget):$($context.RemoteCloudDataDir)/runtime/output", $runtimeDir)
}

if ($Archive) {
    Assert-OracleCommand "tar.exe"
    $archivePath = Join-Path $OutDir "$stamp.tar.gz"
    Invoke-OracleExternal -FilePath "tar.exe" -Arguments @("-czf", $archivePath, "-C", $OutDir, $stamp)
    Write-OracleLog "archive_path=$archivePath"
}

Write-OracleLog "collection_dir=$destinationDir"
