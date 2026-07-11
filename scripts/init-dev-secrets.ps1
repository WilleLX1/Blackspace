[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$secretDir = Join-Path $root "deploy\docker\secrets"
New-Item -ItemType Directory -Force -Path $secretDir | Out-Null

function New-Base64UrlSecret([int]$Length = 32) {
    $bytes = [byte[]]::new($Length)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$databasePassword = New-Base64UrlSecret
$databaseUrl = "postgresql://blackspace:$databasePassword@database/blackspace"

[IO.File]::WriteAllText((Join-Path $secretDir "database_password"), $databasePassword, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $secretDir "database_url"), $databaseUrl, [Text.UTF8Encoding]::new($false))

Write-Host "Development secrets created under deploy/docker/secrets (ignored by Git)."
Write-Host "Create single-use registration invitations with: docker compose -f deploy/docker/compose.yaml exec mailbox blackspace-mailbox invite create"
