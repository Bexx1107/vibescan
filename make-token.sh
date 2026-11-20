#!/usr/bin/env bash
# Generate (or rotate) the VibeScan API token into .env.
# Idempotent-safe: refuses to overwrite an existing token unless --force.
set -euo pipefail
cd "$(dirname "$0")"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

if [ -f .env ] && grep -q '^VIBESCAN_TOKEN=..*' .env && [ "$FORCE" -ne 1 ]; then
  echo ".env already has a VIBESCAN_TOKEN — refusing to overwrite."
  echo "Rotate it with: ./make-token.sh --force"
  exit 0
fi

TOKEN="$(openssl rand -hex 32)"
TMP="$(mktemp .env.XXXXXX)"
trap 'rm -f "$TMP"' EXIT

# Preserve any non-token lines already in .env, then (re)write the token.
if [ -f .env ]; then
  grep -v '^VIBESCAN_TOKEN=' .env | grep -v '^$' > "$TMP" || true
fi
printf 'HOST=0.0.0.0\nPORT=4200\nVIBESCAN_TOKEN=%s\n' "$TOKEN" >> "$TMP"
chmod 600 "$TMP"
mv "$TMP" .env
trap - EXIT

echo "Wrote .env (mode 600) with a fresh 64-hex-char token."
echo "Start:  ./run.sh     (then open  http://<your-ip>:4200/?token=<token> )"
