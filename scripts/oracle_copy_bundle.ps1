[CmdletBinding()]
param(
    [string]$EnvFile = "",
    [string]$RemoteHost = "",
    [string]$User = "",
    [string]$KeyPath = "",
    [int]$SshPort = 0,
    [string]$ProjectDir = "",
    [string]$RemoteUploadDir = "",
    [string]$BundlePath = "",
    [switch]$UploadOnly,
    [switch]$Help
)

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "oracle_common.ps1")

if ($Help) {
    @"
Usage:
  powershell -ExecutionPolicy Bypass -File scripts/oracle_copy_bundle.ps1 -BundlePath <path> [-EnvFile <path>] [-RemoteHost <ip>] [-User <user>] [-KeyPath <path>] [-SshPort <port>] [-ProjectDir <path>] [-RemoteUploadDir <path>] [-UploadOnly]
"@ | Write-Host
    exit 0
}

$resolvedEnvFile = Get-OracleOptionalEnvFile -EnvFile $EnvFile
$settings = Import-OracleProjectEnv -EnvFile $resolvedEnvFile
$context = New-OracleSshContext -Settings $settings -RemoteHost $RemoteHost -RemoteUser $User -SshKeyPath $KeyPath -SshPort $SshPort -RemoteProjectDir $ProjectDir -RemoteUploadDir $RemoteUploadDir

Assert-OracleValue -Value $BundlePath -Label "-BundlePath"
$resolvedBundlePath = Expand-OracleHomePath $BundlePath
Assert-OracleFile $resolvedBundlePath
$manifestPath = [System.IO.Path]::ChangeExtension($resolvedBundlePath, ".manifest.txt")
$remoteBundlePath = "$($context.RemoteUploadDir)/$([System.IO.Path]::GetFileName($resolvedBundlePath))"
$remoteManifestPath = "$($context.RemoteUploadDir)/$([System.IO.Path]::GetFileName($manifestPath))"

$prepareRemote = @'
set -euo pipefail
upload_dir="$1"
project_dir="$2"
remote_user="$3"
sudo -n true >/dev/null 2>&1
install -d -m 755 "$upload_dir"
sudo install -d -m 755 "$project_dir"
sudo chown -R "$remote_user:$remote_user" "$project_dir"
'@
Invoke-OracleRemoteScript -Context $context -ScriptBody $prepareRemote -Arguments @($context.RemoteUploadDir, $context.RemoteProjectDir, $context.RemoteUser)

Invoke-OracleScp -Context $context -Arguments @($resolvedBundlePath, "$($context.RemoteTarget):$remoteBundlePath")
if (Test-Path $manifestPath) {
    Invoke-OracleScp -Context $context -Arguments @($manifestPath, "$($context.RemoteTarget):$remoteManifestPath")
}

if ($UploadOnly) {
    Write-OracleLog "remote_bundle_path=$remoteBundlePath"
    exit 0
}

$extractRemote = @'
set -euo pipefail
bundle_path="$1"
project_dir="$2"
remote_user="$3"
sudo -n true >/dev/null 2>&1
sudo tar -xzf "$bundle_path" -C "$project_dir"
sudo chown -R "$remote_user:$remote_user" "$project_dir"
test -f "$project_dir/docker-compose.cloud-single-node.yml"
test -f "$project_dir/.env.example"
printf "remote_project_dir=%s\n" "$project_dir"
printf "remote_bundle_path=%s\n" "$bundle_path"
'@
Invoke-OracleRemoteScript -Context $context -ScriptBody $extractRemote -Arguments @($remoteBundlePath, $context.RemoteProjectDir, $context.RemoteUser)
