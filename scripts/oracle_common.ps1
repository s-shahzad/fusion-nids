Set-StrictMode -Version Latest

$script:OracleDefaultRemoteProjectDir = "/opt/universal-nids"
$script:OracleDefaultRemoteUploadDir = "/tmp/universal-nids-upload"
$script:OracleDefaultSshPort = 22

function Write-OracleLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host $Message
}

function Throw-OracleError {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw $Message
}

function Get-OracleRepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Get-OracleDefaultEnvFile {
    return Join-Path (Get-OracleRepoRoot) "deployment\oracle_vm.env"
}

function Expand-OracleHomePath {
    param([string]$PathValue)

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $PathValue
    }
    if ($PathValue -eq "~") {
        return $HOME
    }
    if ($PathValue.StartsWith("~/") -or $PathValue.StartsWith("~\")) {
        return Join-Path $HOME $PathValue.Substring(2)
    }
    return $PathValue
}

function Get-OracleOptionalEnvFile {
    param([string]$EnvFile)

    if (-not [string]::IsNullOrWhiteSpace($EnvFile)) {
        return (Expand-OracleHomePath $EnvFile)
    }

    $defaultEnvFile = Get-OracleDefaultEnvFile
    if (Test-Path $defaultEnvFile) {
        return $defaultEnvFile
    }
    return ""
}

function Import-OracleProjectEnv {
    param([string]$EnvFile)

    $settings = @{}
    if ([string]::IsNullOrWhiteSpace($EnvFile)) {
        return $settings
    }
    if (-not (Test-Path $EnvFile)) {
        Throw-OracleError "Oracle project env file not found: $EnvFile"
    }

    foreach ($line in Get-Content -Path $EnvFile -Encoding UTF8) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) {
            continue
        }
        $parts = $trimmed -split "=", 2
        if ($parts.Count -ne 2) {
            continue
        }
        $settings[$parts[0].Trim()] = $parts[1]
    }

    return $settings
}

function Get-OracleSetting {
    param(
        [hashtable]$Settings,
        [string]$Key,
        [string]$DefaultValue = ""
    )

    if ($Settings.ContainsKey($Key) -and -not [string]::IsNullOrWhiteSpace([string]$Settings[$Key])) {
        return [string]$Settings[$Key]
    }
    return $DefaultValue
}

function Assert-OracleCommand {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Throw-OracleError "Required command not found: $Name"
    }
}

function Assert-OracleValue {
    param(
        [string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Throw-OracleError "Missing required argument: $Label"
    }
}

function Assert-OracleFile {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    if (-not (Test-Path $PathValue -PathType Leaf)) {
        Throw-OracleError "Required file not found: $PathValue"
    }
}

function Assert-OracleDirectory {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    if (-not (Test-Path $PathValue -PathType Container)) {
        Throw-OracleError "Required directory not found: $PathValue"
    }
}

function Get-OracleTimestampUtc {
    return (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
}

function Get-OracleHash {
    param([Parameter(Mandatory = $true)][string]$FilePath)
    return (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash.ToLowerInvariant()
}

function Get-OracleDeploymentItems {
    return @(
        ".dockerignore",
        ".env.example",
        "Dockerfile",
        "LEGAL_SAFE_DEVELOPMENT.md",
        "LICENSE",
        "NOTICE",
        "PROVENANCE.md",
        "README.md",
        "RELEASE_BOUNDARY.md",
        "SCAPY_REVIEW.md",
        "THIRD_PARTY.md",
        "config",
        "deployment/oracle_vm.env.example",
        "docker-compose.cloud-single-node.yml",
        "docs/cloud_single_node_profile.md",
        "docs/cloud_storage_boundary.md",
        "docs/cloud_validation_workflow.md",
        "docs/current_status.md",
        "docs/next_actions.md",
        "docs/oracle_vm_cleanup_runbook.md",
        "docs/oracle_vm_deployment_steps.md",
        "docs/oracle_vm_first_boot.md",
        "docs/oracle_vm_nids_runbook.md",
        "models",
        "nids",
        "requirements.txt",
        "rules",
        "scripts",
        "src",
        "state/project_status.json"
    )
}

function Test-OracleDeploymentInputs {
    param([Parameter(Mandatory = $true)][string]$RepoDir)
    foreach ($relativePath in Get-OracleDeploymentItems) {
        $candidate = Join-Path $RepoDir $relativePath
        if (-not (Test-Path $candidate)) {
            Throw-OracleError "Deployment input missing from repository: $relativePath"
        }
    }
}

function Format-OracleArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value) {
        return '""'
    }
    if ($Value -notmatch '[\s"`'']') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Write-OracleCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    $segments = @($FilePath) + ($Arguments | ForEach-Object { Format-OracleArgument $_ })
    Write-Host ("+ " + ($segments -join " "))
}

function Invoke-OracleExternal {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [switch]$CaptureOutput,
        [switch]$AllowFailure
    )

    Write-OracleCommand -FilePath $FilePath -Arguments $Arguments

    if ($CaptureOutput) {
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0 -and -not $AllowFailure) {
            $message = ($output | Out-String).Trim()
            Throw-OracleError "Command failed with exit code ${exitCode}: $FilePath`n$message"
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            Output   = @($output)
        }
    }

    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        Throw-OracleError "Command failed with exit code ${exitCode}: $FilePath"
    }
}

function New-OracleSshContext {
    param(
        [hashtable]$Settings,
        [string]$RemoteHost,
        [string]$RemoteUser,
        [string]$SshKeyPath,
        [int]$SshPort = 0,
        [string]$RemoteProjectDir,
        [string]$RemoteUploadDir
    )

    Assert-OracleCommand "ssh.exe"
    Assert-OracleCommand "scp.exe"

    $resolvedHost = if (-not [string]::IsNullOrWhiteSpace($RemoteHost)) { $RemoteHost } else { Get-OracleSetting -Settings $Settings -Key "ORACLE_VM_HOST" }
    $resolvedUser = if (-not [string]::IsNullOrWhiteSpace($RemoteUser)) { $RemoteUser } else { Get-OracleSetting -Settings $Settings -Key "ORACLE_VM_USER" -DefaultValue "ubuntu" }
    $resolvedKey = if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) { $SshKeyPath } else { Get-OracleSetting -Settings $Settings -Key "ORACLE_VM_SSH_KEY_PATH" }
    $resolvedPort = if ($SshPort -gt 0) { $SshPort } else { [int](Get-OracleSetting -Settings $Settings -Key "ORACLE_VM_SSH_PORT" -DefaultValue ([string]$script:OracleDefaultSshPort)) }
    $resolvedProjectDir = if (-not [string]::IsNullOrWhiteSpace($RemoteProjectDir)) { $RemoteProjectDir } else { Get-OracleSetting -Settings $Settings -Key "ORACLE_VM_PROJECT_DIR" -DefaultValue $script:OracleDefaultRemoteProjectDir }
    $resolvedUploadDir = if (-not [string]::IsNullOrWhiteSpace($RemoteUploadDir)) { $RemoteUploadDir } else { Get-OracleSetting -Settings $Settings -Key "ORACLE_VM_REMOTE_UPLOAD_DIR" -DefaultValue $script:OracleDefaultRemoteUploadDir }

    $resolvedKey = Expand-OracleHomePath $resolvedKey

    Assert-OracleValue -Value $resolvedHost -Label "--host or ORACLE_VM_HOST"
    Assert-OracleValue -Value $resolvedUser -Label "--user or ORACLE_VM_USER"
    Assert-OracleValue -Value $resolvedKey -Label "--key-path or ORACLE_VM_SSH_KEY_PATH"
    Assert-OracleFile $resolvedKey

    $remoteTarget = "$resolvedUser@$resolvedHost"
    $sshArgs = @(
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", $resolvedKey,
        "-p", ([string]$resolvedPort),
        $remoteTarget
    )
    $scpArgs = @(
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", $resolvedKey,
        "-P", ([string]$resolvedPort)
    )

    return [pscustomobject]@{
        RemoteHost         = $resolvedHost
        RemoteUser         = $resolvedUser
        SshKeyPath         = $resolvedKey
        SshPort            = $resolvedPort
        RemoteProjectDir   = $resolvedProjectDir
        RemoteUploadDir    = $resolvedUploadDir
        RemoteTarget       = $remoteTarget
        RemoteCloudDataDir = "$resolvedProjectDir/cloud_data"
        RemoteBundleTempDir = "$resolvedProjectDir/tmp/oracle-uploaded-bundles"
        SshArguments       = $sshArgs
        ScpArguments       = $scpArgs
    }
}

function Invoke-OracleSsh {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [string[]]$RemoteCommand = @(),
        [switch]$CaptureOutput,
        [switch]$AllowFailure
    )
    return Invoke-OracleExternal -FilePath "ssh.exe" -Arguments ($Context.SshArguments + $RemoteCommand) -CaptureOutput:$CaptureOutput -AllowFailure:$AllowFailure
}

function Invoke-OracleScp {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [string[]]$Arguments = @(),
        [switch]$CaptureOutput,
        [switch]$AllowFailure
    )
    return Invoke-OracleExternal -FilePath "scp.exe" -Arguments ($Context.ScpArguments + $Arguments) -CaptureOutput:$CaptureOutput -AllowFailure:$AllowFailure
}

function Invoke-OracleRemoteScript {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$ScriptBody,
        [string[]]$Arguments = @(),
        [switch]$CaptureOutput,
        [switch]$AllowFailure
    )

    $tempFile = New-TemporaryFile
    try {
        [System.IO.File]::WriteAllText($tempFile.FullName, $ScriptBody, [System.Text.UTF8Encoding]::new($false))
        $sshArgs = $Context.SshArguments + @("bash", "-s", "--") + $Arguments
        Write-OracleCommand -FilePath "ssh.exe" -Arguments $sshArgs

        if ($CaptureOutput) {
            $output = Get-Content -Raw -Path $tempFile.FullName | & ssh.exe @sshArgs 2>&1
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 0 -and -not $AllowFailure) {
                $message = ($output | Out-String).Trim()
                Throw-OracleError "Remote script failed with exit code $exitCode`n$message"
            }
            return [pscustomobject]@{
                ExitCode = $exitCode
                Output   = @($output)
            }
        }

        Get-Content -Raw -Path $tempFile.FullName | & ssh.exe @sshArgs
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0 -and -not $AllowFailure) {
            Throw-OracleError "Remote script failed with exit code $exitCode"
        }
    }
    finally {
        Remove-Item -Path $tempFile.FullName -Force -ErrorAction SilentlyContinue
    }
}

function New-OracleDeploymentBundle {
    param(
        [string]$RepoDir = (Get-OracleRepoRoot),
        [string]$OutDir = "",
        [string]$BundleName = ""
    )

    Assert-OracleCommand "tar.exe"
    Assert-OracleDirectory $RepoDir
    Test-OracleDeploymentInputs -RepoDir $RepoDir

    if ([string]::IsNullOrWhiteSpace($OutDir)) {
        $OutDir = Join-Path $RepoDir "release\deployment-bundles"
    }
    if (-not (Test-Path $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    }
    if ([string]::IsNullOrWhiteSpace($BundleName)) {
        $BundleName = "universal-nids-oracle-$(Get-OracleTimestampUtc).tar.gz"
    }

    $bundlePath = Join-Path $OutDir $BundleName
    $manifestPath = [System.IO.Path]::ChangeExtension($bundlePath, ".manifest.txt")

    $tarArgs = @("-czf", $bundlePath, "-C", $RepoDir) + (Get-OracleDeploymentItems)
    Invoke-OracleExternal -FilePath "tar.exe" -Arguments $tarArgs

    $bundleSha256 = Get-OracleHash -FilePath $bundlePath
    $manifestLines = @(
        "generated_at_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
        "repo_dir=$RepoDir",
        "bundle_path=$bundlePath",
        "bundle_sha256=$bundleSha256",
        "included_paths="
    ) + (Get-OracleDeploymentItems)
    Set-Content -Path $manifestPath -Value $manifestLines -Encoding UTF8

    return [pscustomobject]@{
        BundlePath   = $bundlePath
        ManifestPath = $manifestPath
        BundleSha256 = $bundleSha256
    }
}
