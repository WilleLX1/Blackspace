[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$lock = Get-Content -Raw (Join-Path $root "tor-bundle.lock.json") | ConvertFrom-Json
$archive = Join-Path $env:TEMP "tor-expert-bundle-$($lock.tor_browser_bundle_version).tar.gz"
$extract = Join-Path $env:TEMP "blackspace-tor-$($lock.tor_browser_bundle_version)"
$tauri = Join-Path $root "apps\desktop-windows\src-tauri"
$binaryDir = Join-Path $tauri "binaries"
$supportDir = Join-Path $tauri "tor-support"

Invoke-WebRequest -Uri $lock.url -OutFile $archive
$actual = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
if ($actual -ne $lock.sha256) {
    throw "Tor bundle hash mismatch. Expected $($lock.sha256), received $actual."
}

if (Test-Path $extract) { Remove-Item -Recurse -Force -LiteralPath $extract }
New-Item -ItemType Directory -Force -Path $extract, $binaryDir, $supportDir | Out-Null
tar -xzf $archive -C $extract

$tor = Get-ChildItem -Path $extract -Recurse -Filter tor.exe | Select-Object -First 1
$geoip = Get-ChildItem -Path $extract -Recurse -File -Filter geoip | Select-Object -First 1
$geoip6 = Get-ChildItem -Path $extract -Recurse -File -Filter geoip6 | Select-Object -First 1
if (-not $tor -or -not $geoip -or -not $geoip6) { throw "The verified Tor bundle has an unexpected layout." }

Copy-Item -Force -LiteralPath $tor.FullName -Destination (Join-Path $binaryDir "tor-x86_64-pc-windows-msvc.exe")
Copy-Item -Force -LiteralPath $geoip.FullName -Destination (Join-Path $supportDir "geoip")
Copy-Item -Force -LiteralPath $geoip6.FullName -Destination (Join-Path $supportDir "geoip6")
Get-ChildItem -Path $tor.DirectoryName -File -Filter *.dll | ForEach-Object {
    Copy-Item -Force -LiteralPath $_.FullName -Destination (Join-Path $supportDir $_.Name)
}

Write-Host "Verified and prepared Tor $($lock.tor_version) for Tauri."
Write-Host "Before updating tor-bundle.lock.json, manually verify the Tor Project .asc signature documented in the release process."
