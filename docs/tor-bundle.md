# Managed Tor bundle

The Windows client pins the Tor Project Expert Bundle described by `tor-bundle.lock.json`. The current lock is Tor Browser bundle 15.0.17 containing Tor 0.4.9.11 for Windows x86-64.

```powershell
.\scripts\fetch-tor.ps1
```

The script downloads the official archive, refuses a SHA-256 mismatch, extracts `tor.exe`, GeoIP data and runtime DLLs, and places them in ignored Tauri build directories. The executable is packaged as a Tauri sidecar; support files are packaged as resources.

The committed checksum pins an already reviewed artifact. Before changing the lock file, manually verify the detached `.asc` signature from `signature_url` against the Tor Browser Developers signing key using the Tor Project's current verification instructions. Record the verified version and checksum in the same review that updates the lock.

At runtime, the Rust backend:

- starts Tor in client-only mode;
- uses cookie-authenticated automatic control and SOCKS ports;
- waits for 100% bootstrap;
- uses `SafeSocks`, `SafeLogging`, extended onion errors and `IsolateSOCKSAuth`;
- creates one randomly authenticated SOCKS identity and connection pool per canonical onion destination for the lifetime of the managed-Tor session;
- never shares a SOCKS identity between destinations and clears every cached client when Tor stops or restarts;
- permits only canonical `http://<56-character-v3>.onion` origins;
- disables redirects and provides no direct HTTP client;
- blocks all mailbox operations when Tor is unavailable.

The UI has no shell permission and cannot select a direct fallback.
