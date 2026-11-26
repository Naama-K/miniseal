#!/bin/sh
# Container start: make sure there is a signing key, then run the server.
set -eu

if [ -z "${MINISEAL_SIGNING_KEY:-}" ]; then
  # No key passed in: use (and on first start, create) one in the volume,
  # so `docker compose up` needs no setup and the key survives restarts.
  MINISEAL_SIGNING_KEY_FILE="${MINISEAL_SIGNING_KEY_FILE:-/data/signing.key}"
  export MINISEAL_SIGNING_KEY_FILE
  python -m app.crypto ensure "$MINISEAL_SIGNING_KEY_FILE"
fi

exec "$@"
