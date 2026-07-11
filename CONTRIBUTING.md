# Contributing

Keep changes inside the documented v0.1 private-alpha security boundary: plaintext belongs only inside an unlocked encrypted client vault; never add clearnet fallback, remote production scripts, sensitive logging, or a shared read/write capability.

Run the checks in [docs/development.md](docs/development.md) before submitting changes. Protocol changes begin in the Rust wire types and must regenerate OpenAPI and TypeScript contracts. Cryptographic and Tor dependency changes require explicit security review and updated lock evidence.

Do not commit generated secrets, database volumes, onion-service keys, Tor binaries, local capability profiles or diagnostic logs.
