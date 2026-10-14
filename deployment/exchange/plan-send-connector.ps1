<#
.SYNOPSIS
  PLAN ONLY: prints the commands that would create a Send connector from Exchange to the MSP gateway.

.DESCRIPTION
  This script NEVER changes Exchange; it validates input and prints a plan for an operator to
  review (MSP 1.1, sections 20-22). Outbound delivery to the Internet through the gateway is
  DISABLED BY DEFAULT in MSP 1.1: the plan is only produced for a test address space (an isolated
  domain, an SMTP sink or a controlled smart host). The wildcard address space '*' is refused
  unless -AllowWildcardAddressSpace is given, and even then the script only prints a plan with a
  loud warning.

.PARAMETER AddressSpace
  Address space the connector would serve, for example 'lab.example'. Required.

.PARAMETER GatewayHost
  Gateway host name or address used as the smart host. Required.

.PARAMETER GatewayPort
  Port of the gateway internal (Exchange-facing) listener. Default 2525.

.PARAMETER Name
  Connector name. Default: "MSP Gateway Outbound".

.PARAMETER SourceServer
  Exchange transport server that will send through the gateway. Required.

.PARAMETER AllowWildcardAddressSpace
  Allow '*' as an address space (all Internet mail). NOT recommended for MSP 1.1.

.EXAMPLE
  .\plan-send-connector.ps1 -AddressSpace lab.example -GatewayHost gw.corp.example -SourceServer EX01

  MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^(\*|[A-Za-z0-9.-]{3,253})$')][string]$AddressSpace,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9.-]{1,253}$')][string]$GatewayHost,
    [ValidateRange(1, 65535)][int]$GatewayPort = 2525,
    [ValidatePattern('^[A-Za-z0-9 ._-]{1,64}$')][string]$Name = "MSP Gateway Outbound",
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$SourceServer,
    [switch]$AllowWildcardAddressSpace
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($AddressSpace -eq "*" -and -not $AllowWildcardAddressSpace) {
    throw "Address space '*' would route all outbound Internet mail through the gateway. " +
          "Outbound Internet delivery is disabled by default in MSP 1.1; use a test address space."
}

Write-Host "================================================================" -ForegroundColor Yellow
Write-Host " MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER" -ForegroundColor Yellow
Write-Host " PLAN ONLY - nothing has been changed on any server." -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
if ($AddressSpace -eq "*") {
    Write-Warning "The plan routes ALL outbound mail through the gateway. This is not approved in MSP 1.1."
}

$plan = @"
# 1. Review the current state (read-only):
.\inspect.ps1 -OutFile .\before.json

# 2. Create the connector (operator, change window, test address space first):
New-SendConnector -Name '$Name' ``
    -Usage Custom ``
    -AddressSpaces 'SMTP:${AddressSpace};100' ``
    -SmartHosts '$GatewayHost' ``
    -Port $GatewayPort ``
    -SmartHostAuthMechanism None ``
    -RequireTLS `$true ``
    -TlsAuthLevel CertificateValidation ``
    -SourceTransportServers '$SourceServer' ``
    -DNSRoutingEnabled `$false

# 3. Send a test message to a recipient in '$AddressSpace' and confirm it arrives at the sink or
#    controlled smart host, NOT on the Internet.

# 4. Verify (read-only):
.\verify-connectors.ps1 -Name '$Name' -Kind Send

# 5. Roll back if anything is wrong (see rollback-plan.md):
Remove-SendConnector -Identity '$Name' -Confirm:`$true
"@

Write-Output $plan
