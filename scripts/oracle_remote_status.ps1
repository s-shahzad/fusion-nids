[CmdletBinding()]
param(
    [string]$EnvFile = "",
    [string]$RemoteHost = "",
    [string]$User = "",
    [string]$KeyPath = "",
    [int]$SshPort = 0,
    [string]$ProjectDir = "",
    [string]$Service = "nids-runtime",
    [int]$Tail = 50,
    [switch]$Follow,
    [switch]$Help
)

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "oracle_common.ps1")

if ($Help) {
    @"
Usage:
  powershell -ExecutionPolicy Bypass -File scripts/oracle_remote_status.ps1 [-EnvFile <path>] [-RemoteHost <ip>] [-User <user>] [-KeyPath <path>] [-SshPort <port>] [-ProjectDir <path>] [-Service <name>] [-Tail <lines>] [-Follow]
"@ | Write-Host
    exit 0
}

$resolvedEnvFile = Get-OracleOptionalEnvFile -EnvFile $EnvFile
$settings = Import-OracleProjectEnv -EnvFile $resolvedEnvFile
$context = New-OracleSshContext -Settings $settings -RemoteHost $RemoteHost -RemoteUser $User -SshKeyPath $KeyPath -SshPort $SshPort -RemoteProjectDir $ProjectDir -RemoteUploadDir ""

$statusRemote = @'
set -euo pipefail
project_dir="$1"
service_name="$2"
tail_lines="$3"
follow_logs="$4"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"
cloud_root="$project_dir/cloud_data"
if sudo docker compose version >/dev/null 2>&1; then
  compose_base=(sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
else
  compose_base=(sudo docker-compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
fi

printf "project_dir=%s\n" "$project_dir"
printf "cloud_root=%s\n" "$cloud_root"
df -h "$project_dir" "$cloud_root" || true
"${compose_base[@]}" ps -a || true

if [[ -d "$cloud_root/runtime/logs" ]]; then
  printf "\nlatest_runtime_logs\n"
  ls -1t "$cloud_root/runtime/logs" | head -n 5 || true
fi

if [[ -d "$cloud_root/manifests" ]]; then
  printf "\nlatest_manifests\n"
  ls -1t "$cloud_root/manifests" | head -n 5 || true
fi

printf "\ncompose_logs_%s\n" "$service_name"
if [[ "$follow_logs" == "1" ]]; then
  "${compose_base[@]}" logs -f --tail "$tail_lines" "$service_name"
else
  "${compose_base[@]}" logs --tail "$tail_lines" "$service_name" || true
fi
'@

Invoke-OracleRemoteScript -Context $context -ScriptBody $statusRemote -Arguments @($context.RemoteProjectDir, $Service, ([string]$Tail), ($(if ($Follow) { "1" } else { "0" })))
