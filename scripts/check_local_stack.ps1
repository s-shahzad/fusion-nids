[CmdletBinding()]
param(
    [string]$NidsUrl = "http://127.0.0.1:8010/health",
    [string]$VectorUrl = "http://127.0.0.1:8011/health",
    [string]$OllamaUrl = "http://127.0.0.1:11434/api/version"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Endpoint {
    param([string]$Url)
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
        return @{ url = $Url; ok = $true; status = [int]$response.StatusCode }
    } catch {
        return @{ url = $Url; ok = $false; error = $_.Exception.Message }
    }
}

$results = @(
    Test-Endpoint -Url $NidsUrl
    Test-Endpoint -Url $VectorUrl
    Test-Endpoint -Url $OllamaUrl
)

$results | ConvertTo-Json -Depth 4
