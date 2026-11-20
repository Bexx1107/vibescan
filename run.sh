#!/usr/bin/env bash
# VibeScan launcher — internal tool
set -euo pipefail
cd "$(dirname "$0")"

# Load .env (KEY=VALUE, # comments ignored) without clobbering real env vars.
# An explicitly-exported VIBESCAN_ALLOW_INSECURE=1 in the calling shell wins
# over whatever .env says, so enabling/disabling no-auth is a temporary,
# per-command choice rather than a permanent edit to the file.
ENV_ALLOW_INSECURE=""
if [ -f .env ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; esac
    key="${line%%=*}"; val="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"           # trim trailing ws on key
    case "$key" in *[!A-Za-z0-9_]*) continue ;; esac
    if [ "$key" = "VIBESCAN_ALLOW_INSECURE" ]; then ENV_ALLOW_INSECURE="$val"; fi
    if [ -z "${!key:-}" ]; then export "$key=$val"; fi
  done < .env
fi
# .env may set VIBESCAN_ALLOW_INSECURE (persistent); an exported value in the
# calling shell overrides it (temporary). Whichever is non-empty and not "1"
# means "not insecure".
if [ -n "${VIBESCAN_ALLOW_INSECURE:-}" ]; then
  case "$VIBESCAN_ALLOW_INSECURE" in 1) ;; *) unset VIBESCAN_ALLOW_INSECURE ;; esac
elif [ "$ENV_ALLOW_INSECURE" = "1" ]; then
  export VIBESCAN_ALLOW_INSECURE=1
fi

export PORT="${PORT:-4200}"
# P0: default to loopback. Exposing beyond loopback requires VIBESCAN_TOKEN;
# server.js refuses to start otherwise (reports hold un-redacted secrets/PII).
export HOST="${HOST:-127.0.0.1}"

LOOPBACK=0
case "$HOST" in 127.0.0.1|localhost|::1) LOOPBACK=1 ;; esac

echo "Starting VibeScan on http://${HOST}:${PORT}"
if [ "$LOOPBACK" -eq 0 ]; then
  if [ -z "${VIBESCAN_TOKEN:-}" ] && [ "${VIBESCAN_ALLOW_INSECURE:-}" != "1" ]; then
    echo "Refusing to start: HOST=${HOST} is non-loopback but VIBESCAN_TOKEN is unset." >&2
    echo "Run: ./make-token.sh   (writes .env with a random token), or set VIBESCAN_TOKEN." >&2
    echo "No-auth opt-out (DANGEROUS): VIBESCAN_ALLOW_INSECURE=1 ./run.sh" >&2
    exit 1
  fi
  if [ "${VIBESCAN_ALLOW_INSECURE:-}" = "1" ]; then
    echo "⚠️  Running with NO AUTH (VIBESCAN_ALLOW_INSECURE=1) — anyone who can reach this port (LAN + Tailscale) can read every report."
  elif [ -n "${VIBESCAN_TOKEN:-}" ]; then
    echo "Auth: /api/* requires  Authorization: Bearer <your token>  (from .env)"
    echo "UI in a browser: the page will ask for it — paste it once and it is remembered."
  fi
fi
exec node server.js
