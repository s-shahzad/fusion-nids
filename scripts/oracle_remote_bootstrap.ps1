[CmdletBinding()]
param(
    [string]$EnvFile = "",
    [string]$RemoteHost = "",
    [string]$User = "",
    [string]$KeyPath = "",
    [int]$SshPort = 0,
    [string]$ProjectDir = "",
    [switch]$Help
)

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "oracle_common.ps1")

if ($Help) {
    @"
Usage:
  powershell -ExecutionPolicy Bypass -File scripts/oracle_remote_bootstrap.ps1 [-EnvFile <path>] [-RemoteHost <ip>] [-User <user>] [-KeyPath <path>] [-SshPort <port>] [-ProjectDir <path>]
"@ | Write-Host
    exit 0
}

$resolvedEnvFile = Get-OracleOptionalEnvFile -EnvFile $EnvFile
$settings = Import-OracleProjectEnv -EnvFile $resolvedEnvFile
$context = New-OracleSshContext -Settings $settings -RemoteHost $RemoteHost -RemoteUser $User -SshKeyPath $KeyPath -SshPort $SshPort -RemoteProjectDir $ProjectDir -RemoteUploadDir ""

$remoteScript = @'
set -euo pipefail
remote_user="$1"
project_dir="$2"
cloud_root="$3"

sudo -n true >/dev/null 2>&1 || {
  echo "Passwordless sudo is required for bootstrap." >&2
  exit 1
}

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update

base_packages=(ca-certificates curl git python3 rsync tar)
missing_packages=()
for package_name in "${base_packages[@]}"; do
  if ! dpkg -s "$package_name" >/dev/null 2>&1; then
    missing_packages+=("$package_name")
  fi
done
if [[ ${#missing_packages[@]} -gt 0 ]]; then
  sudo apt-get install -y "${missing_packages[@]}"
fi

if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get install -y docker.io
fi

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  for compose_package in docker-compose-v2 docker-compose-plugin docker-compose; do
    if apt-cache show "$compose_package" >/dev/null 2>&1; then
      sudo apt-get install -y "$compose_package"
      break
    fi
  done
fi

sudo systemctl enable --now docker

layout_paths=(
  "$project_dir"
  "$cloud_root/runtime/output"
  "$cloud_root/runtime/logs"
  "$cloud_root/runtime/reports"
  "$cloud_root/runtime/artifacts/incoming"
  "$cloud_root/runtime/artifacts/processed"
  "$cloud_root/runtime/artifacts/quarantine"
  "$cloud_root/lab_generated/bundles"
  "$cloud_root/lab_generated/archive"
  "$cloud_root/replay/staging"
  "$cloud_root/archive/output_bundles"
  "$cloud_root/manifests"
  "$project_dir/tmp/oracle-uploaded-bundles"
)
for path_item in "${layout_paths[@]}"; do
  sudo install -d -m 755 "$path_item"
done
sudo chown -R "$remote_user:$remote_user" "$project_dir"

sudo docker version >/dev/null 2>&1 || {
  echo "Docker is installed but not responding." >&2
  exit 1
}

if docker compose version >/dev/null 2>&1; then
  compose_version="$(docker compose version --short)"
elif command -v docker-compose >/dev/null 2>&1; then
  compose_version="$(docker-compose version --short)"
else
  echo "Docker Compose is not available after bootstrap." >&2
  exit 1
fi

printf "docker_ok=true\n"
printf "compose_version=%s\n" "$compose_version"
printf "remote_project_dir=%s\n" "$project_dir"
printf "remote_cloud_data_dir=%s\n" "$cloud_root"
'@

Invoke-OracleRemoteScript -Context $context -ScriptBody $remoteScript -Arguments @($context.RemoteUser, $context.RemoteProjectDir, $context.RemoteCloudDataDir)
