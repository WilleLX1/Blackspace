# syntax=docker/dockerfile:1.7
FROM rust:1.91-bookworm AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY services/mailbox ./services/mailbox
COPY apps/desktop-windows/src-tauri/Cargo.toml apps/desktop-windows/src-tauri/Cargo.toml
COPY apps/desktop-windows/src-tauri/src apps/desktop-windows/src-tauri/src
RUN cargo build --locked --release -p blackspace-mailbox

FROM debian:bookworm-slim
RUN groupadd --system --gid 10001 blackspace \
    && useradd --system --uid 10001 --gid blackspace --home-dir /nonexistent --shell /usr/sbin/nologin blackspace \
    && apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /source/target/release/blackspace-mailbox /usr/local/bin/blackspace-mailbox
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/blackspace-mailbox"]
