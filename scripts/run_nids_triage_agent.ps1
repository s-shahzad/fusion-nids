param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = "Stop"

$OpenClawCmd = Join-Path $env:APPDATA "npm\openclaw.cmd"
if (-not (Test-Path $OpenClawCmd)) {
    Write-Error "openclaw.cmd was not found at $OpenClawCmd"
    exit 1
}

$ChunkSize = 6000
$MaxPromptChars = 24000
$ChunkTimeoutSeconds = 1200

function Get-MessageText {
    param([string[]]$ArgsIn)

    for ($i = 0; $i -lt $ArgsIn.Count; $i++) {
        $token = $ArgsIn[$i]
        if (($token -eq "-m" -or $token -eq "--message") -and $i + 1 -lt $ArgsIn.Count) {
            return $ArgsIn[$i + 1]
        }
        if ($token.StartsWith("--message=")) {
            return $token.Substring("--message=".Length)
        }
    }

    if ([Console]::IsInputRedirected) {
        return [Console]::In.ReadToEnd()
    }

    return $null
}

function Resolve-MessageText {
    param([string]$MessageText)

    if ([string]::IsNullOrWhiteSpace($MessageText)) {
        return $MessageText
    }

    if ($MessageText.StartsWith("@")) {
        $candidatePath = $MessageText.Substring(1)
        if (Test-Path $candidatePath) {
            return Get-Content -LiteralPath $candidatePath -Raw
        }
    }

    return $MessageText
}

function Remove-MessageArgs {
    param([string[]]$ArgsIn)

    $result = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $ArgsIn.Count; $i++) {
        $token = $ArgsIn[$i]
        if ($token -eq "-m" -or $token -eq "--message") {
            $i++
            continue
        }
        if ($token.StartsWith("--message=")) {
            continue
        }
        [void]$result.Add($token)
    }
    return [string[]]$result
}

function Get-SessionId {
    param([string[]]$ArgsIn)

    for ($i = 0; $i -lt $ArgsIn.Count; $i++) {
        $token = $ArgsIn[$i]
        if ($token -eq "--session-id" -and $i + 1 -lt $ArgsIn.Count) {
            return $ArgsIn[$i + 1]
        }
        if ($token.StartsWith("--session-id=")) {
            return $token.Substring("--session-id=".Length)
        }
    }

    return $null
}

function Has-Timeout {
    param([string[]]$ArgsIn)

    foreach ($token in $ArgsIn) {
        if ($token -eq "--timeout" -or $token.StartsWith("--timeout=")) {
            return $true
        }
    }

    return $false
}

function Has-Thinking {
    param([string[]]$ArgsIn)

    foreach ($token in $ArgsIn) {
        if ($token -eq "--thinking" -or $token.StartsWith("--thinking=")) {
            return $true
        }
    }

    return $false
}

function Split-IntoChunks {
    param(
        [string]$Text,
        [int]$Size
    )

    $chunks = New-Object System.Collections.Generic.List[string]
    $offset = 0
    while ($offset -lt $Text.Length) {
        $length = [Math]::Min($Size, $Text.Length - $offset)
        [void]$chunks.Add($Text.Substring($offset, $length))
        $offset += $length
    }
    return [string[]]$chunks
}

function Invoke-OpenClaw {
    param([string[]]$Arguments)

    & $OpenClawCmd @Arguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$messageText = Resolve-MessageText (Get-MessageText -ArgsIn $CliArgs)
$passThroughArgs = Remove-MessageArgs -ArgsIn $CliArgs

$baseArgs = @("agent", "--agent", "nids-triage")
$baseArgs += $passThroughArgs
if (-not (Has-Thinking -ArgsIn $baseArgs)) {
    $baseArgs += @("--thinking", "off")
}

if (-not $messageText) {
    Invoke-OpenClaw -Arguments $baseArgs
    exit 0
}

$normalized = $messageText -replace "`r`n", "`n"
$wasTruncated = $false
if ($normalized.Length -gt $MaxPromptChars) {
    $normalized = $normalized.Substring(0, $MaxPromptChars)
    $wasTruncated = $true
}

if ($normalized.Length -le $ChunkSize) {
    $singleArgs = @($baseArgs + @("--message", $normalized))
    if (-not (Has-Timeout -ArgsIn $singleArgs)) {
        $singleArgs += @("--timeout", $ChunkTimeoutSeconds)
    }
    Invoke-OpenClaw -Arguments $singleArgs
    exit 0
}

$sessionId = Get-SessionId -ArgsIn $baseArgs
if (-not $sessionId) {
    $sessionId = "nids-triage-local-" + [Guid]::NewGuid().ToString("N")
    $baseArgs += @("--session-id", $sessionId)
}
if (-not (Has-Timeout -ArgsIn $baseArgs)) {
    $baseArgs += @("--timeout", $ChunkTimeoutSeconds)
}

$chunks = Split-IntoChunks -Text $normalized -Size $ChunkSize
$total = $chunks.Count

for ($i = 0; $i -lt $total; $i++) {
    $chunkNum = $i + 1
    $chunkEnvelope = @"
Large local prompt delivery in progress for offline nids-triage execution.
Store this as prompt chunk $chunkNum of $total and do not perform the final task yet.
Reply with exactly: CHUNK $chunkNum/$total RECEIVED

---BEGIN CHUNK $chunkNum/$total---
$($chunks[$i])
---END CHUNK $chunkNum/$total---
"@
    $chunkArgs = @($baseArgs + @("--message", $chunkEnvelope))
    Invoke-OpenClaw -Arguments $chunkArgs
}

$finalEnvelope = if ($wasTruncated) {
@"
All prompt chunks have been delivered.
Execute the user's request using the complete chunked content above.
The original input exceeded the local safety ceiling and was truncated to $MaxPromptChars characters before delivery.
"@
} else {
@"
All prompt chunks have been delivered.
Execute the user's request using the complete chunked content above.
"@
}

$finalArgs = @($baseArgs + @("--message", $finalEnvelope))
Invoke-OpenClaw -Arguments $finalArgs
