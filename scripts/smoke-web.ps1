[CmdletBinding()]
param(
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [string]$RegistrationToken = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $RegistrationToken) {
    $invitation = docker compose -f (Join-Path $root "deploy\docker\compose.yaml") exec -T mailbox blackspace-mailbox invite create
    if ($LASTEXITCODE -ne 0) { throw "Could not create a registration invitation." }
    $RegistrationToken = ([Uri]$invitation.Trim()).Fragment.Substring(1).Split('=')[1]
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url([string]$Value) {
    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    $base64 += '=' * ((4 - ($base64.Length % 4)) % 4)
    return [Convert]::FromBase64String($base64)
}

function New-Capability {
    $bytes = [byte[]]::new(32)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ConvertTo-Base64Url $bytes
}

function Get-CapabilityVerifier([string]$Purpose, [string]$Capability) {
    $domain = [Text.Encoding]::UTF8.GetBytes("blackspace:v1:${Purpose}:")
    $secret = ConvertFrom-Base64Url $Capability
    $input = [byte[]]::new($domain.Length + $secret.Length)
    [Array]::Copy($domain, 0, $input, 0, $domain.Length)
    [Array]::Copy($secret, 0, $input, $domain.Length, $secret.Length)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ConvertTo-Base64Url ($sha.ComputeHash($input)) } finally { $sha.Dispose() }
}

$read = New-Capability
$admin = New-Capability
$deposit = New-Capability
$smokeIdentity = cargo run --quiet -p blackspace-core --bin generate-smoke-key-package | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Could not generate a valid OpenMLS smoke key package." }
$identity = $smokeIdentity.identity_public_key
$packageId = [Guid]::NewGuid().ToString()
$provisionBody = @{
    identity_public_key = $identity
    read_capability_verifier = Get-CapabilityVerifier "read" $read
    admin_capability_verifier = Get-CapabilityVerifier "admin" $admin
    initial_deposit_capability_verifier = Get-CapabilityVerifier "deposit" $deposit
    initial_deposit_expires_at = $null
    key_packages = @(@{
        package_id = $packageId
        protocol_version = 1
        ciphersuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        identity_public_key = $identity
        key_package = $smokeIdentity.key_package
        expires_at = [DateTimeOffset]::UtcNow.AddDays(30).AddMinutes(-1).ToUnixTimeSeconds()
    })
} | ConvertTo-Json -Compress

$mailbox = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/mailboxes" -Headers @{
    Authorization = "BlackspaceRegistration $RegistrationToken"
} -ContentType "application/json" -Body $provisionBody
$mailboxRetry = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/mailboxes" -Headers @{
    Authorization = "BlackspaceRegistration $RegistrationToken"
} -ContentType "application/json" -Body $provisionBody
if ($mailboxRetry.mailbox_id -ne $mailbox.mailbox_id -or
    $mailboxRetry.initial_deposit_capability_id -ne $mailbox.initial_deposit_capability_id) {
    throw "An identical registration retry did not return the original mailbox."
}

$ciphertextBytes = [byte[]]::new(4096)
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($ciphertextBytes) } finally { $rng.Dispose() }
$envelopeId = [Guid]::NewGuid().ToString()
$envelopeBody = @{
    version = 1
    envelope_id = $envelopeId
    expires_at = [DateTimeOffset]::UtcNow.AddDays(14).ToUnixTimeSeconds()
    size_class = 4096
    ciphertext = ConvertTo-Base64Url $ciphertextBytes
} | ConvertTo-Json -Compress

$accepted = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/deposit/envelopes" -Headers @{
    Authorization = "BlackspaceDeposit $deposit"
} -ContentType "application/blackspace-envelope+json" -Body $envelopeBody
if (-not $accepted.accepted) { throw "The envelope was not accepted." }

$pull = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/mailbox/pull" -Headers @{
    Authorization = "BlackspaceRead $read"
} -ContentType "application/json" -Body '{"limit":100}'
if ($pull.envelopes.Count -ne 1 -or $pull.envelopes[0].envelope_id -ne $envelopeId) {
    throw "The pulled envelope did not match the deposited envelope."
}

$ackBody = @{
    acknowledgement_tokens = @($pull.envelopes[0].acknowledgement_token)
} | ConvertTo-Json -Compress
$ack = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/mailbox/ack" -Headers @{
    Authorization = "BlackspaceRead $read"
} -ContentType "application/json" -Body $ackBody
if ($ack.acknowledged -ne 1) { throw "Acknowledgement did not delete exactly one envelope." }

$emptyPull = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/mailbox/pull" -Headers @{
    Authorization = "BlackspaceRead $read"
} -ContentType "application/json" -Body '{"limit":100}'
if ($emptyPull.envelopes.Count -ne 0) { throw "The acknowledged envelope remained queued." }

[pscustomobject]@{
    mailbox_id = $mailbox.mailbox_id
    envelope_id = $envelopeId
    deposited_bytes = 4096
    acknowledged = $ack.acknowledged
    remaining = $emptyPull.envelopes.Count
}
