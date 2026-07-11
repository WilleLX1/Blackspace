[CmdletBinding()]
param(
    [ValidateRange(1, 168)]
    [int]$Hours = 24
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $root "deploy\docker\compose.yaml"
$hostname = (docker compose -f $compose exec -T tor cat /var/lib/tor/blackspace/hostname).Trim()
if ($LASTEXITCODE -ne 0 -or $hostname -notmatch '^[a-z2-7]{56}\.onion$') {
    throw "The Tor onion hostname is not ready. Check the tor container first."
}
docker compose -f $compose exec -T -e "BLACKSPACE_ONION_ORIGIN=http://$hostname" mailbox blackspace-mailbox invite create --hours $Hours
if ($LASTEXITCODE -ne 0) { throw "The mailbox could not create a registration invitation." }
