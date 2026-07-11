# Blackspace

Blackspace is an invite-only, self-hosted, one-to-one encrypted messenger for Windows, Tor Browser, and HTTPS-capable browsers.

> [!WARNING]
> Blackspace `v0.1.0` is an unaudited private alpha. It is not suitable for high-risk or real-world sensitive communications.

The mailbox server stores fixed-size opaque envelopes. Message plaintext, display names, contacts, mailbox capabilities, identity private keys, and MLS state remain in encrypted client storage.

The browser policy permits WebAssembly compilation with the narrow CSP source `'wasm-unsafe-eval'`. It does not enable JavaScript `'unsafe-eval'`.

## What works

- Responsive messenger shell with onboarding, lock/unlock, contacts, message requests, unread state, drafts, delivery status, retry, offline outbox, fingerprint verification, settings, and recovery export/import.
- Real two-member MLS conversations through OpenMLS `0.8.1` using `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- Client-generated Ed25519 identities and signed, single-use OpenMLS key packages.
- Versioned, validated CBOR application payloads inside padded MLS ciphertext.
- Argon2id (`64 MiB`, 3 iterations, parallelism 1) encrypted PWA vault in IndexedDB.
- SQLite Windows vault with secure deletion, bounded journaling, AES-256-GCM records, and a random key protected by both current-user DPAPI and the app-lock passphrase.
- Encrypted recovery kits that preserve identity/history while excluding reusable MLS group and pending outbox state. Import rotates mailbox access and starts fresh sessions.
- Rust/Axum/PostgreSQL mailbox with one-time registration invitations, purpose-separated capability verifiers, quotas, expiry, acknowledgement deletion, and key-package claim races handled transactionally.
- Onion-only default Compose deployment, loopback-only development profile, and optional Caddy HTTPS profile.
- Managed Tor Expert Bundle sidecar on Windows with cookie-authenticated control port, automatic SOCKS discovery, bootstrap monitoring, clean shutdown, and no clearnet fallback.

Deferred: groups, channels, attachments, calls, reactions, edits, presence, public discovery, moderation, and multi-device synchronization.

## Quick start

Requirements:

- Rust 1.85 or newer
- Node.js 22 and pnpm 10.2.1
- Docker Desktop or Docker Engine with Compose
- PowerShell 5.1 or newer for the commands below

Install dependencies and start the loopback development stack:

```powershell
& "$env:LOCALAPPDATA\pnpm\pnpm.exe" install
.\scripts\init-dev-secrets.ps1
docker compose -f deploy/docker/compose.yaml --profile web-dev up -d --build
```

If pnpm is not installed directly, use `npx --yes pnpm@10.2.1` in its place.

Create a single-use registration invitation:

```powershell
.\scripts\new-registration-invite.ps1
```

The default lifetime is 24 hours; the maximum is seven days:

```powershell
.\scripts\new-registration-invite.ps1 -Hours 168
```

Open `http://127.0.0.1:8080`, paste the invitation, choose a private display name and vault passphrase, and finish onboarding. This origin is persistently labelled **Compatibility Web — HTTP development only**.

The generated onion hostname is stored in the `onion_keys` volume. Open that address in Tor Browser for Tor Web mode.

## Quick start Linux

This is the simplest way to run a new onion-only Blackspace server on a 64-bit Linux machine or a Raspberry Pi 4/5. A Pi with at least 4 GB of RAM and Raspberry Pi OS Lite (64-bit) is recommended. The default deployment exposes no host ports, so you do not need port forwarding or a public IP address.

Install [Docker Engine for Debian](https://docs.docker.com/engine/install/debian/) with the Compose plugin, then install the remaining tools:

```sh
sudo apt update
sudo apt install -y git openssl
sudo systemctl enable --now docker
docker version
docker compose version
```

The commands below assume your user can run Docker. Either prefix Docker commands with `sudo`, or follow Docker's [Linux post-install instructions](https://docs.docker.com/engine/install/linux-postinstall/). Clone or copy this repository to the server, then enter it:

```sh
git clone https://github.com/WilleLX1/Blackspace.git 
cd Blackspace
```

### Raspberry Pi preparation

The pinned Tor Project Onimages container is currently AMD64-only. On a 64-bit Raspberry Pi, install the distribution's QEMU user-mode support and use the included Compose override. Only Tor is emulated; PostgreSQL, the Rust mailbox, and the web edge run natively on ARM64.

```sh
sudo apt install -y qemu-user-static
sudo systemctl restart systemd-binfmt
test -e /proc/sys/fs/binfmt_misc/qemu-x86_64
```

If the final command fails, reboot the Pi once and run it again. Do not use this override on an ordinary AMD64 Linux server.

Create private database secrets and start the onion-only stack:

```sh
sh scripts/init-dev-secrets.sh
docker compose \
  -f deploy/docker/compose.yaml \
  -f deploy/docker/compose.raspberry-pi.yaml \
  up -d --build
```

On an AMD64 Linux server, omit the Raspberry Pi override:

```sh
sh scripts/init-dev-secrets.sh
docker compose -f deploy/docker/compose.yaml up -d --build
```

The first Raspberry Pi build may take tens of minutes because it compiles the Rust mailbox locally. Check that the database is healthy and the remaining services are running:

```sh
docker compose -f deploy/docker/compose.yaml ps
docker compose -f deploy/docker/compose.yaml logs --tail=100 mailbox tor
```

Read the generated onion address:

```sh
docker compose -f deploy/docker/compose.yaml exec -T tor \
  cat /var/lib/tor/blackspace/hostname
```

Open `http://<generated-hostname>.onion` in Tor Browser. Create a single-use registration invitation with a 24-hour lifetime:

```sh
sh scripts/new-registration-invite.sh
```

To choose a lifetime from 1 to 168 hours, pass the number as the first argument:

```sh
sh scripts/new-registration-invite.sh 168
```

All services use `restart: unless-stopped`, so they return after a reboot when Docker starts. Keep the Pi updated, use reliable storage and power, and never publish the PostgreSQL or mailbox container ports.

The Docker volumes named `blackspace_onion_keys` and `blackspace_mailbox_database`, plus `deploy/docker/secrets`, are server-critical. Losing the onion-key volume changes the server address. Copying it exposes the onion service's private key. Back up both volumes only while the stack is stopped, encrypt the backup, and keep it offline.

This quick start creates a fresh server. Copying only the repository does **not** transfer existing accounts. Moving a live installation from Docker Desktop requires an offline migration of both named volumes and the secrets directory; stop the old server first and do not run the old and new copies simultaneously with the same onion keys.

## Windows Tor Native

Fetch and verify the pinned Windows Tor Expert Bundle, then run Tauri:

```powershell
.\scripts\fetch-tor.ps1
& "$env:LOCALAPPDATA\pnpm\pnpm.exe" --filter @blackspace/desktop tauri dev
```

The native webview has no generic HTTP or shell permission. Remote requests are Rust commands and fail closed unless managed Tor is fully bootstrapped. Only canonical `http://<56-character-v3>.onion` origins on port 80 are accepted.

Tor Native assigns a random SOCKS isolation identity to each canonical onion destination. Requests to the same destination reuse that destination-only connection pool; different destinations never share an identity, and all cached clients are erased whenever managed Tor stops or restarts. Native transport failures are mapped to a small redacted error vocabulary before reaching the UI.

The bundle is excluded from Git and verified against [tor-bundle.lock.json](tor-bundle.lock.json). The Tor Project Onimages container used by Compose is also pinned by digest and remains experimental.

## Using the messenger

1. Each user joins their mailbox server using a different one-time server invitation.
2. One user chooses **Create invitation** and shares the contact URI/QR through a trusted channel.
3. The other user chooses **Add contact**, pastes or scans it, and sends a first message.
4. The recipient reviews the conversation under **Message requests** and accepts or blocks it.
5. Both users compare the full fingerprint in **Verify identity** using another trusted channel.

Each contact invitation contains a distinct write-only deposit capability and public identity. It never grants mailbox read or administration access. Secrets are URI fragments and are not sent in HTTP request paths.

Messages move through `queued`, `server accepted`, `delivered`, or `failed`. The client persists the exact encrypted envelope before attempting delivery, so offline and manual retries reuse the same envelope ID. There are encrypted delivery receipts, but no read receipts or typing indicators.

## Transport modes

| Mode | Routing | Important limitation |
|---|---|---|
| Tor Native | Managed Tor SOCKS5 hostname proxy to recipient onion | Strongest implemented network mode; endpoint compromise is still out of scope |
| Tor Web | Recipient onion directly in Tor Browser | Browser behavior and service-worker support must be feature-detected |
| HTTPS Web | Recipient's explicitly advertised HTTPS gateway | Cross-origin requests expose the PWA `Origin` header to the gateway |
| Compatibility Web Dev | Loopback HTTP only | Development mode, never represented as HTTPS |

There is no clearnet fallback. Tor modes do not substitute HTTPS, and HTTPS Web reports contacts without an advertised gateway as Tor-only.

## Architecture

```text
React shell
  ├─ blackspace-core WASM: identity, OpenMLS, CBOR, recovery-state reset
  ├─ PWA vault: encrypted IndexedDB
  └─ Tauri commands: managed Tor networking + DPAPI/SQLite vault

Recipient origin
  └─ edge proxy
      ├─ static PWA
      └─ /v1 → Rust mailbox → PostgreSQL opaque queue
```

The default Compose network publishes no host mailbox or database ports. Onion port 80 routes to the internal edge proxy. The `web-dev` profile publishes only `127.0.0.1:8080`.

Onion keys are persisted separately. Backing them up preserves the onion address but also copies the onion service's private key; protect backups accordingly.

## Protocol summary

- `GET /v1/info`
- `POST /v1/mailboxes` — `BlackspaceRegistration`
- `POST /v1/mailbox/key-packages` — `BlackspaceAdmin`
- `POST /v1/deposit/key-packages/claim` — `BlackspaceDeposit`
- `POST /v1/deposit/envelopes` — `BlackspaceDeposit`
- `POST /v1/mailbox/pull` and `/v1/mailbox/ack` — `BlackspaceRead`
- `POST`/`DELETE /v1/mailbox/deposit-capabilities` — `BlackspaceAdmin`
- `POST /v1/mailbox/recover` — old `BlackspaceAdmin`

Envelope size classes are exactly 1, 4, 16, 64, or 256 KiB. The server enforces 1,000 queued envelopes per mailbox, 14-day default retention, 30-day maximum retention, batches of 100, duplicate rejection, and 30 deposits per minute per capability.

Only server info, key-package claim, and envelope deposit allow credentialless cross-origin browser requests. Registration, pull, acknowledgement, administration, and recovery remain same-origin.

See [docs/protocol-v1.md](docs/protocol-v1.md) and the committed [OpenAPI contract](docs/openapi-v1.json).

## Development checks

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
& "$env:LOCALAPPDATA\pnpm\pnpm.exe" check
& "$env:LOCALAPPDATA\pnpm\pnpm.exe" test
& "$env:LOCALAPPDATA\pnpm\pnpm.exe" build
& "$env:LOCALAPPDATA\pnpm\pnpm.exe" contracts:check
.\scripts\smoke-web.ps1
```

Regenerate the committed browser core after changing its WASM exports:

```powershell
cargo build -p blackspace-core --release --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/blackspace_core.wasm --target web --out-dir apps/pwa/src/wasm --out-name blackspace_core
```

PostgreSQL integration tests run when `BLACKSPACE_TEST_DATABASE_URL` is set. The real-Tor smoke path remains optional because bootstrap depends on the public Tor network.

## HTTPS profile

Set `BLACKSPACE_HTTPS_DOMAIN`, `BLACKSPACE_HTTPS_ORIGIN`, and `BLACKSPACE_ACME_EMAIL`, then run:

```powershell
docker compose -f deploy/docker/compose.yaml --profile https up -d --build
```

Caddy terminates TLS and renews certificates. HTTPS Web can deliver only to gateways explicitly included in contact invitations.

## Upgrades and reset

The old v0.0.1 diagnostic mailboxes do not contain identities or key packages and are not upgradable. Reset development data before onboarding v0.1 accounts:

```powershell
docker compose -f deploy/docker/compose.yaml down -v
```

## Security boundaries

Blackspace does not hide all metadata. A mailbox observes timing, envelope size class, expiry, capability use, and queue behavior. A recipient HTTPS gateway also sees the requesting PWA origin. Tor Native and Tor Web have different client-integrity and metadata properties.

DPAPI protects data at rest from other Windows users; it does not defend against malware already executing as the current user. Browser and SSD storage cannot guarantee physical erasure of old pages. A malicious client can reveal its own plaintext and keys.

Read [SECURITY.md](SECURITY.md) before testing and report vulnerabilities privately without including real identities, capabilities, onion keys, recovery kits, or production data.

## Repository layout

```text
apps/pwa/                       React/Vite PWA and generated core WASM
apps/desktop-windows/src-tauri/ Tauri shell, Tor supervisor, native vault
crates/blackspace-core/         OpenMLS, identity, CBOR, vault/recovery primitives
crates/blackspace-protocol/     Authoritative API types and OpenAPI
crates/blackspace-capabilities/ Purpose-separated capability verification
crates/blackspace-tor/          Onion URL and Tor control parsing
services/mailbox/               Axum/PostgreSQL mailbox and migrations
deploy/docker/                  Compose, nginx, Caddy, Tor topology
scripts/                        Setup, Tor fetch, invitation, contracts, smoke
```

Packages are unpublished and no project license has been selected.
