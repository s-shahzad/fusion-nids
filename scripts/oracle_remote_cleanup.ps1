[CmdletBinding()]
param(
    [string]$EnvFile = "",
    [string]$RemoteHost = "",
    [string]$User = "",
    [string]$KeyPath = "",
    [int]$SshPort = 0,
    [string]$ProjectDir = "",
    [int]$OlderThanHours = 24,
    [switch]$Apply,
    [switch]$Stop,
    [switch]$CleanArtifactIntake,
    [switch]$CleanUploadCache,
    [switch]$Help
)

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "oracle_common.ps1")

if ($Help) {
    @"
Usage:
  powershell -ExecutionPolicy Bypass -File scripts/oracle_remote_cleanup.ps1 [-EnvFile <path>] [-RemoteHost <ip>] [-User <user>] [-KeyPath <path>] [-SshPort <port>] [-ProjectDir <path>] [-OlderThanHours <hours>] [-Apply] [-Stop] [-CleanArtifactIntake] [-CleanUploadCache]
"@ | Write-Host
    exit 0
}

$resolvedEnvFile = Get-OracleOptionalEnvFile -EnvFile $EnvFile
$settings = Import-OracleProjectEnv -EnvFile $resolvedEnvFile
$context = New-OracleSshContext -Settings $settings -RemoteHost $RemoteHost -RemoteUser $User -SshKeyPath $KeyPath -SshPort $SshPort -RemoteProjectDir $ProjectDir -RemoteUploadDir ""

$cleanupRemote = @'
set -euo pipefail
project_dir="$1"
older_than_hours="$2"
apply_changes="$3"
stop_containers="$4"
clean_artifact_intake="$5"
clean_upload_cache="$6"
cloud_root="$project_dir/cloud_data"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"
minutes="$(( older_than_hours * 60 ))"

cleanup_args=(python3 scripts/cloud_validation_workflow.py cleanup-temp --root "$cloud_root" --older-than-hours "$older_than_hours")
if [[ "$apply_changes" == "1" ]]; then
  cleanup_args+=(--apply)
fi
(cd "$project_dir" && "${cleanup_args[@]}")

clean_find_path() {
  target_path="$1"
  label="$2"
  if [[ ! -d "$target_path" ]]; then
    return 0
  fi
  printf "\n%s_candidates\n" "$label"
  find "$target_path" -mindepth 1 -maxdepth 1 -mmin +"$minutes" -print || true
  if [[ "$apply_changes" == "1" ]]; then
    find "$target_path" -mindepth 1 -maxdepth 1 -mmin +"$minutes" -exec rm -rf {} +
  fi
}

if [[ "$clean_artifact_intake" == "1" ]]; then
  clean_find_path "$cloud_root/runtime/artifacts/incoming" "artifact_intake"
fi

if [[ "$clean_upload_cache" == "1" ]]; then
  clean_find_path "$project_dir/tmp/oracle-uploaded-bundles" "upload_cache"
fi

if [[ "$stop_containers" == "1" ]]; then
  if sudo docker compose version >/dev/null 2>&1; then
    sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file" down
  else
    sudo docker-compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file" down
  fi
fi
'@

Invoke-OracleRemoteScript -Context $context -ScriptBody $cleanupRemote -Arguments @(
    $context.RemoteProjectDir,
    ([string]$OlderThanHours),
    ($(if ($Apply) { "1" } else { "0" })),
    ($(if ($Stop) { "1" } else { "0" })),
    ($(if ($CleanArtifactIntake) { "1" } else { "0" })),
    ($(if ($CleanUploadCache) { "1" } else { "0" }))
)
