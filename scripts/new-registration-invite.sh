#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/deploy/docker/compose.yaml"
HOURS=${1:-24}
case "$HOURS" in *[!0-9]*|'') echo "hours must be 1..168" >&2; exit 1;; esac
if [ "$HOURS" -lt 1 ] || [ "$HOURS" -gt 168 ]; then echo "hours must be 1..168" >&2; exit 1; fi
HOSTNAME=$(docker compose -f "$COMPOSE" exec -T tor cat /var/lib/tor/blackspace/hostname | tr -d '\r\n')
docker compose -f "$COMPOSE" exec -T -e "BLACKSPACE_ONION_ORIGIN=http://$HOSTNAME" mailbox blackspace-mailbox invite create --hours "$HOURS"
