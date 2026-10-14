<#
.SYNOPSIS
  PLAN ONLY: prints the commands that would create a dedicated Receive connector for the MSP gateway.

.DESCRIPTION
  This script NEVER changes Exchange. It validates its input and prints a plan (the exact commands
  an operator would review and run by hand, from a change window, after approval). There is no
  -Apply switch on purpose: "no automatic production changes without an operator" (MSP 1.1,
  sections 20-21) is enforced by the script not being able to apply anything.

  The connector the plan describes:
    * accepts SMTP only from the gateway addresses you pass in -GatewayIp (no ranges wider than /24
      unless you say so explicitly, and never 0.0.0.0/0);
    * requires TLS;
    * grants no permission that would turn Exchange into an open relay for external recipients
      (no Accept-Any-Recipient, no Accept-Authoritative-Domain-Sender for other senders).

.PARAMETER GatewayIp
  One or more gateway addresses (IPv4 or IPv4/CIDR). Required.

.PARAMETER Server
  Exchange server the connector belongs to. Required.

.PARAMETER Name
  Connector name. Default: "MSP Gateway Receive".

.PARAMETER Fqdn
  FQDN the connector announces. Required: it must match the TLS certificate on the server.

.PARAMETER BindingIp
  Address to bind on the Exchange server. Required, so the connector never shares a binding with
  the default connectors.

.PARAMETER Port
  TCP port to bind. Default 2525 (a dedicated port, not the default 25 of the client connectors).

.PARAMETER MaxMessageSizeMB
  Maximum message size in MB. Must not be smaller than the gateway limit, otherwise a message the
  gateway accepted would be refused by Exchange. Default 50.

.PARAMETER AllowWideRange
  Permit gateway ranges wider than /24. Still prints a warning.

.EXAMPLE
  .\plan-receive-connector.ps1 -GatewayIp 192.0.2.10 -Server EX01 -Fqdn ex01.corp.example -BindingIp 192.0.2.50

  MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$GatewayIp,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$Server,
    [ValidatePattern('^[A-Za-z0-9 ._-]{1,64}$')][string]$Name = "MSP Gateway Receive",
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9.-]{3,253}$')][string]$Fqdn,
    [Parameter(Mandatory)][ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')][string]$BindingIp,
    [ValidateRange(1, 65535)][int]$Port = 2525,
    [ValidateRange(1, 2048)][int]$MaxMessageSizeMB = 50,
    [switch]$AllowWideRange
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-GatewayRange([string]$Value) {
    if ($Value -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?$') {
        throw "Not an IPv4 address or range: '$Value'"
    }
    foreach ($i in 1..4) {
        if ([int]$Matches[$i] -gt 255) { throw "Octet out of range in '$Value'" }
    }
    $prefix = if ($Matches[5]) { [int]$Matches[5] } else { 32 }
    if ($prefix -gt 32) { throw "Prefix out of range in '$Value'" }
    if ($prefix -eq 0) { throw "Range '$Value' matches every address and is never acceptable." }
    if ($prefix -lt 24 -and -not $AllowWideRange) {
        throw "Range '$Value' is wider than /24. Pass -AllowWideRange only if that is really intended."
    }
    return $prefix
}

$wide = $false
foreach ($ip in $GatewayIp) {
    if ((Test-GatewayRange $ip) -lt 24) { $wide = $true }
}

Write-Host "================================================================" -ForegroundColor Yellow
Write-Host " MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER" -ForegroundColor Yellow
Write-Host " PLAN ONLY - nothing has been changed on any server." -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
if ($wide) { Write-Warning "A gateway range wider than /24 is part of this plan. Re-check it." }

$ranges = ($GatewayIp | ForEach-Object { "'$_'" }) -join ", "
$sizeBytes = [int64]$MaxMessageSizeMB * 1MB

$plan = @"
# 1. Review the current state first (read-only):
.\inspect.ps1 -OutFile .\before.json

# 2. Create the dedicated connector (run by an operator, in a change window):
New-ReceiveConnector -Name '$Name' -Server '$Server' ``
    -Usage Custom ``
    -Bindings '${BindingIp}:$Port' ``
    -RemoteIPRanges $ranges ``
    -Fqdn '$Fqdn' ``
    -AuthMechanism Tls ``
    -RequireTLS `$true ``
    -PermissionGroups AnonymousUsers ``
    -MaxMessageSize ${sizeBytes}B ``
    -ProtocolLoggingLevel Verbose

# 3. Do NOT grant relay rights. The connector must not receive:
#      ms-Exch-SMTP-Accept-Any-Recipient
#    Mail for external recipients must be refused by this connector.

# 4. Verify (read-only) and keep the result with the change record:
.\verify-connectors.ps1 -Name '$Name' -Server '$Server' -GatewayIp $ranges

# 5. Roll back if anything is wrong (see rollback-plan.md):
Remove-ReceiveConnector -Identity '$Server\$Name' -Confirm:`$true
"@

Write-Output $plan
