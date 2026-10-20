<#
.SYNOPSIS
  Read-only inventory of the Exchange transport configuration (MSP 1.1, section 21).

.DESCRIPTION
  Collects what the gateway integration depends on: Receive connectors, Send connectors, accepted
  domains and the message size limit. Nothing is changed. The script uses read-only Get-* cmdlets
  only; the repository test tests/unit/test_exchange_scripts.py fails if a state-changing cmdlet
  appears in the executable part of any script in this directory.

  Run it from the Exchange Management Shell on an Exchange server. The result is a JSON file the
  operator reads before deciding anything; it contains no passwords or private keys.

.PARAMETER OutFile
  Where to write the JSON report. Default: .\exchange-inventory.json

.EXAMPLE
  .\inspect.ps1 -OutFile C:\Temp\exchange-inventory.json

  MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER
#>
[CmdletBinding()]
param(
    [string]$OutFile = ".\exchange-inventory.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

foreach ($required in "Get-ReceiveConnector", "Get-SendConnector", "Get-AcceptedDomain", "Get-TransportConfig") {
    if (-not (Get-Command $required -ErrorAction SilentlyContinue)) {
        throw "This script must run in the Exchange Management Shell ($required not found)."
    }
}

Write-Host "MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER" -ForegroundColor Yellow
Write-Host "Read-only inventory. No changes will be made." -ForegroundColor Cyan

$receive = Get-ReceiveConnector | ForEach-Object {
    [pscustomobject]@{
        Identity         = [string]$_.Identity
        Server           = [string]$_.Server
        Bindings         = @($_.Bindings | ForEach-Object { [string]$_ })
        RemoteIPRanges   = @($_.RemoteIPRanges | ForEach-Object { [string]$_ })
        AuthMechanism    = [string]$_.AuthMechanism
        PermissionGroups = [string]$_.PermissionGroups
        RequireTLS       = [bool]$_.RequireTLS
        Fqdn             = [string]$_.Fqdn
        MaxMessageSize   = [string]$_.MaxMessageSize
        Enabled          = [bool]$_.Enabled
    }
}

$send = Get-SendConnector | ForEach-Object {
    [pscustomobject]@{
        Identity         = [string]$_.Identity
        AddressSpaces    = @($_.AddressSpaces | ForEach-Object { [string]$_ })
        SmartHosts       = @($_.SmartHosts | ForEach-Object { [string]$_ })
        SmartHostAuth    = [string]$_.SmartHostAuthMechanism
        RequireTLS       = [bool]$_.RequireTLS
        TlsAuthLevel     = [string]$_.TlsAuthLevel
        Enabled          = [bool]$_.Enabled
    }
}

$domains = Get-AcceptedDomain | ForEach-Object {
    [pscustomobject]@{ Name = [string]$_.DomainName; Type = [string]$_.DomainType; Default = [bool]$_.Default }
}

$config = Get-TransportConfig
$report = [pscustomobject]@{
    GeneratedAt       = (Get-Date).ToUniversalTime().ToString("o")
    Note              = "MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER"
    ReceiveConnectors = @($receive)
    SendConnectors    = @($send)
    AcceptedDomains   = @($domains)
    MaxReceiveSize    = [string]$config.MaxReceiveSize
    MaxSendSize       = [string]$config.MaxSendSize
}

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host ("Report written to {0}" -f $OutFile) -ForegroundColor Green
