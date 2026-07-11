# Blackspace private-alpha development

Blackspace v0.1.0 is an invited one-to-one messaging alpha. It contains a Rust/OpenMLS client core, the opaque PostgreSQL mailbox, a managed-Tor Windows shell, and a shared React PWA. It is unaudited and must not be represented as production-secure software.

## Local stack

```powershell
npx --yes pnpm@10.2.1 install
.\scripts\init-dev-secrets.ps1
docker compose -f deploy/docker/compose.yaml --profile web-dev up -d --build
```

Create each registration invitation with the helper, which reads the generated onion hostname without persisting it in a shell history:

```powershell
.\scripts\new-registration-invite.ps1
.\scripts\new-registration-invite.ps1 -Hours 168
```

Invitations are single-use. The default expiry is 24 hours and the maximum is seven days. The `web-dev` profile publishes only `127.0.0.1:8080`; mailbox and PostgreSQL ports remain private.

## Checks

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npx --yes pnpm@10.2.1 check
npx --yes pnpm@10.2.1 test
npx --yes pnpm@10.2.1 build
npx --yes pnpm@10.2.1 contracts:check
docker compose -f deploy/docker/compose.yaml config
```

Set `BLACKSPACE_TEST_DATABASE_URL` to enable PostgreSQL integration tests. Tor bootstrap smoke testing remains optional because it depends on the public Tor network.

## State and upgrades

The v0.0.1 diagnostic mailboxes have no identity or key packages and cannot be upgraded into chat accounts. Reset development volumes before private-alpha onboarding:

```powershell
docker compose -f deploy/docker/compose.yaml down -v
```

PWA identity keys, mailbox capabilities, contacts, drafts, message history, and OpenMLS state are stored only inside the encrypted IndexedDB vault. Windows Tor Native stores the encrypted records in SQLite and protects the random vault key with current-user DPAPI plus the Argon2id app-lock passphrase. The service worker caches versioned static assets and never `/v1` requests. Closing the client locks the vault; background delivery is not attempted while locked.

The optional `https` Compose profile requires `BLACKSPACE_HTTPS_DOMAIN`, `BLACKSPACE_HTTPS_ORIGIN`, and `BLACKSPACE_ACME_EMAIL`. Normal-browser web mode never falls back to onion delivery, and Tor modes never fall back to HTTPS.
