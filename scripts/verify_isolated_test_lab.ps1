[CmdletBinding()]
param(
    [string]$LabRoot = "$env:USERPROFILE\NIDS_Workspace\NIDS_TestLab",
    [string]$DistributionName = "Ubuntu"
)

$ErrorActionPreference = "Stop"

$labRootResolved = [System.IO.Path]::GetFullPath($LabRoot)
$ruleName = "NIDS Test Lab - Block WSL Inbound To Host"

Write-Host "Lab root: $labRootResolved"
Write-Host "Directories:"
foreach ($path in @(
    $labRootResolved,
    (Join-Path $labRootResolved "pcaps"),
    (Join-Path $labRootResolved "output"),
    (Join-Path $labRootResolved "reports"),
    (Join-Path $labRootResolved "logs")
)) {
    Write-Host ("  {0}: {1}" -f $path, (Test-Path $path))
}

Write-Host ""
Write-Host "WSL:"
try {
    $wslList = (& wsl.exe -l -q 2>$null) | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    if ($wslList.Count -eq 0) {
        Write-Host "  No WSL distributions installed."
    } else {
        foreach ($item in $wslList) {
            $mark = if ($item -eq $DistributionName) { "*" } else { "-" }
            Write-Host "  $mark $item"
        }
    }
} catch {
    Write-Host "  WSL is not installed."
}

Write-Host ""
Write-Host "Firewall:"
$rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($rule) {
    $addressFilter = $rule | Get-NetFirewallAddressFilter
    Write-Host ("  Rule: {0}" -f $rule.DisplayName)
    Write-Host ("  Enabled: {0}" -f $rule.Enabled)
    Write-Host ("  RemoteAddress: {0}" -f ($addressFilter.RemoteAddress -join ", "))
} else {
    Write-Host "  Firewall block rule not found."
}

Write-Host ""
Write-Host "WSL Adapter:"
$adapter = Get-NetIPAddress -InterfaceAlias "vEthernet (WSL)" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -and $_.IPAddress -notlike "169.254*" } |
    Select-Object -First 1
if ($adapter) {
    Write-Host ("  vEthernet (WSL): {0}/{1}" -f $adapter.IPAddress, $adapter.PrefixLength)
} else {
    Write-Host "  vEthernet (WSL) is not active."
}
