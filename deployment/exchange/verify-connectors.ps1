<#
.SYNOPSIS
  Read-only verification of the gateway connectors on Exchange (MSP 1.1, section 21).

.DESCRIPTION
  Reads the connector (Get-ReceiveConnector / Get-SendConnector / Get-ADPermission) and prints PASS
  or FAIL for each safety property. It changes nothing. Exit code 0 means every check passed, 1
  means at least one failed, 2 means the check could not be performed.

  Receive connector checks:
    * exists and is enabled;
    * TLS is required;
    * remote IP ranges are exactly the gateway addresses (no more, never 0.0.0.0/0);
    * no relay permission (Accept-Any-Recipient) is granted, so Exchange is not an open relay.

  Send connector checks:
    * exists and is enabled;
    * TLS is required with certificate validation;
    * DNS routing is off (all mail goes to the gateway, not directly to the Internet);
    * the address space is not '*' (outbound Internet delivery is disabled by default in MSP 1.1).

.PARAMETER Name
  Connector name. Required.

.PARAMETER Kind
  Receive (default) or Send.

.PARAMETER Server
  Exchange server (Receive connectors).

.PARAMETER GatewayIp
  Expected remote IP ranges (Receive connectors).

.EXAMPLE
  .\verify-connectors.ps1 -Name 'MSP Gateway Receive' -Server EX01 -GatewayIp 192.0.2.10

  MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9 ._-]{1,64}$')][string]$Name,
    [ValidateSet("Receive", "Send")][string]$Kind = "Receive",
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$Server,
    [string[]]$GatewayIp = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$results = [System.Collections.Generic.List[object]]::new()
function Write-CheckResult([string]$Check, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Check = $Check; Result = $(if ($Passed) { "PASS" } else { "FAIL" }); Detail = $Detail })
}

Write-Host "MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER" -ForegroundColor Yellow
Write-Host "Read-only verification. No changes will be made." -ForegroundColor Cyan

try {
    if ($Kind -eq "Receive") {
        if (-not $Server) { throw "-Server is required for Receive connectors." }
        $connector = Get-ReceiveConnector -Identity "$Server\$Name"
        Write-CheckResult "connector exists" $true "$Server\$Name"
        Write-CheckResult "enabled" ([bool]$connector.Enabled) ([string]$connector.Enabled)
        Write-CheckResult "TLS required" ([bool]$connector.RequireTLS) ([string]$connector.RequireTLS)

        $actual = @($connector.RemoteIPRanges | ForEach-Object { ([string]$_).Trim() })
        $anyAddress = @($actual | Where-Object { $_ -match '^(0\.0\.0\.0|0\.0\.0\.0-255\.255\.255\.255|::)' -or $_ -match '/0$' })
        Write-CheckResult "no match-all remote range" ($anyAddress.Count -eq 0) ($actual -join ", ")
        if ($GatewayIp.Count -gt 0) {
            $unexpected = @($actual | Where-Object { $GatewayIp -notcontains $_ })
            $missing = @($GatewayIp | Where-Object { $actual -notcontains $_ })
            Write-CheckResult "remote ranges are exactly the gateway" (($unexpected.Count -eq 0) -and ($missing.Count -eq 0)) `
                ("unexpected: [{0}] missing: [{1}]" -f ($unexpected -join ", "), ($missing -join ", "))
        }

        $relay = @(Get-ADPermission -Identity $connector.Identity |
            Where-Object { $_.ExtendedRights -contains "ms-Exch-SMTP-Accept-Any-Recipient" -and -not $_.Deny })
        Write-CheckResult "no relay permission (Accept-Any-Recipient)" ($relay.Count -eq 0) ("grants: {0}" -f $relay.Count)
    }
    else {
        $connector = Get-SendConnector -Identity $Name
        Write-CheckResult "connector exists" $true $Name
        Write-CheckResult "enabled" ([bool]$connector.Enabled) ([string]$connector.Enabled)
        Write-CheckResult "TLS required" ([bool]$connector.RequireTLS) ([string]$connector.RequireTLS)
        Write-CheckResult "certificate validated" ([string]$connector.TlsAuthLevel -eq "CertificateValidation") ([string]$connector.TlsAuthLevel)
        Write-CheckResult "DNS routing disabled" (-not [bool]$connector.DNSRoutingEnabled) ([string]$connector.DNSRoutingEnabled)
        $spaces = @($connector.AddressSpaces | ForEach-Object { [string]$_ })
        $wild = @($spaces | Where-Object { $_ -match '^(SMTP:)?\*(;|$)' })
        Write-CheckResult "address space is not '*'" ($wild.Count -eq 0) ($spaces -join ", ")
    }
}
catch {
    Write-Error ("Verification could not be performed: {0}" -f $_.Exception.Message)
    exit 2
}

$results | Format-Table -AutoSize | Out-String | Write-Host
if (@($results | Where-Object { $_.Result -eq "FAIL" }).Count -gt 0) {
    Write-Host "RESULT: FAIL" -ForegroundColor Red
    exit 1
}
Write-Host "RESULT: PASS" -ForegroundColor Green
exit 0
