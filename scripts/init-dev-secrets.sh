#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SECRET_DIR="$ROOT/deploy/docker/secrets"
mkdir -p "$SECRET_DIR"

database_password=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
database_url="postgresql://blackspace:${database_password}@database/blackspace"

umask 077
printf '%s' "$database_password" > "$SECRET_DIR/database_password"
printf '%s' "$database_url" > "$SECRET_DIR/database_url"

printf '%s\n' "Development secrets created under deploy/docker/secrets (ignored by Git)."
printf '%s\n' "Create invitations with: docker compose -f deploy/docker/compose.yaml exec mailbox blackspace-mailbox invite create"
