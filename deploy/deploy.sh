#!/usr/bin/env bash
# Deploy VibeScan to a host. Idempotent; run it twice and the second run is a
# no-op except for the restart.
#
#   VIBESCAN_DOMAIN=example.com ./deploy/deploy.sh root@203.0.113.10          # dry run
#   VIBESCAN_DOMAIN=example.com ./deploy/deploy.sh root@203.0.113.10 --apply  # actually deploy
#
# What it does, in order:
#   1. rsync the source tree (no node_modules, no data/, no .env).
#   2. seed data/vibescan.db if a local copy exists and the target has none.
#   3. create the service user, dirs and /etc/vibescan/public.env.
#   4. install + enable vibescan-public.service.
#   5. install the Caddy block for $VIBESCAN_DOMAIN and VALIDATE before reloading.

set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:?usage: deploy.sh user@host [--apply]}"
APPLY=0
[ "${2:-}" = "--apply" ] && APPLY=1
DOMAIN="${VIBESCAN_DOMAIN:-your-domain.example}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
run() { if [ "$APPLY" = 1 ]; then "$@"; else printf '   [dry] %s\n' "$*"; fi; }

say "Pre-flight (domain: $DOMAIN)"
run npm test >/dev/null
if [ "$APPLY" = 1 ]; then npm test >/dev/null 2>&1 || { echo "tests failed — refusing to deploy"; exit 1; }; fi
echo "   tests passed"

say "1/5 source → /home/vibescan/app"
run ssh "$TARGET" 'id -u vibescan >/dev/null 2>&1 || useradd --system --home /home/vibescan --shell /usr/sbin/nologin vibescan; install -d -o vibescan -g vibescan -m 0750 /home/vibescan/app/data /etc/vibescan'
rsync_args=(-a --delete --itemize-changes
  --exclude '.env' --exclude 'node_modules' --exclude '.git'
  --exclude 'data/' --exclude '*.log')
run rsync "${rsync_args[@]}" ./ "$TARGET:/home/vibescan/app/"

say "2/5 database setup"
# Seed a starter database on first deploy only if one exists locally; subsequent deploys preserve the live DB.
run ssh "$TARGET" 'if [ -f /home/vibescan/app/data/vibescan.db ]; then echo "   db present, keeping it"; else echo "   no remote db yet (app initializes schema on first start)"; fi'
if [ "$APPLY" = 1 ]; then
  if [ -f data/vibescan.db ]; then
    ssh "$TARGET" 'test -f /home/vibescan/app/data/vibescan.db' || \
      rsync -a data/vibescan.db "$TARGET:/home/vibescan/app/data/vibescan.db"
  fi
  ssh "$TARGET" 'chown -R vibescan:vibescan /home/vibescan/app/data && if [ -f /home/vibescan/app/data/vibescan.db ]; then chmod 0600 /home/vibescan/app/data/vibescan.db; fi'
fi

say "3/5 env file"
if [ "$APPLY" = 1 ]; then
  ssh "$TARGET" "DOMAIN='$DOMAIN' bash -s" <<'ENVEOF'
if [ ! -f /etc/vibescan/public.env ]; then
  TOKEN=$(openssl rand -hex 32)
  sed -e "s|__GENERATE_ME__|$TOKEN|" -e "s|https://your-domain\.example|https://$DOMAIN|g" \
    /home/vibescan/app/deploy/public.env.example > /etc/vibescan/public.env
  chown root:vibescan /etc/vibescan/public.env
  chmod 0640 /etc/vibescan/public.env
  echo "   wrote /etc/vibescan/public.env with a fresh token"
fi
ENVEOF
else
  run ssh "$TARGET" 'test -f /etc/vibescan/public.env || echo "   [dry] would create /etc/vibescan/public.env"'
fi

say "4/5 systemd unit"
run rsync -a deploy/vibescan-public.service "$TARGET:/etc/systemd/system/vibescan-public.service"
run ssh "$TARGET" 'systemctl daemon-reload && systemctl enable --now vibescan-public.service && systemctl restart vibescan-public.service && systemctl --no-pager --lines=5 status vibescan-public.service'

say "5/5 Caddy"
run ssh "$TARGET" 'cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.pre-vibescan.$(date +%s)'
if [ "$APPLY" = 1 ]; then
  TMP_CADDY=$(mktemp)
  sed "s|your-domain\.example|$DOMAIN|g" deploy/Caddyfile.vibescan > "$TMP_CADDY"
  scp -q "$TMP_CADDY" "$TARGET:/tmp/vibescan.caddy"
  rm -f "$TMP_CADDY"
  ssh "$TARGET" "DOMAIN='$DOMAIN' bash -s" <<'CADDYEOF'
set -e
F=/etc/caddy/Caddyfile
if grep -q "^# >>> $DOMAIN" "$F"; then
  python3 - "$F" "$DOMAIN" <<"PY"
import re, sys
p, dom = sys.argv[1], sys.argv[2]
src = open(p).read()
block = open("/tmp/vibescan.caddy").read().rstrip() + "\n"
esc = re.escape(dom)
new, n = re.subn(rf"# >>> {esc}\n.*?# <<< {esc}\n",
                 f"# >>> {dom}\n" + block + f"# <<< {dom}\n", src, flags=re.S)
if n != 1:
    sys.exit("expected exactly one managed block, found %d" % n)
open(p, "w").write(new)
print("   replaced managed block")
PY
else
  printf "\n# >>> %s\n" "$DOMAIN" >> "$F"
  cat /tmp/vibescan.caddy >> "$F"
  printf "# <<< %s\n" "$DOMAIN" >> "$F"
  echo "   appended managed block"
fi
caddy fmt --overwrite "$F"
LOGF=/var/log/caddy/vibescan-access.log
install -d -m 0750 /var/log/caddy
install -o caddy -g caddy -m 0600 /dev/null "$LOGF" 2>/dev/null || touch "$LOGF"
chown caddy:caddy "$LOGF" && chmod 0600 "$LOGF"
if caddy validate --config "$F" --adapter caddyfile >/dev/null 2>&1; then
  systemctl reload caddy
  echo "   caddy reloaded"
else
  caddy validate --config "$F" --adapter caddyfile
  echo "!! Caddyfile INVALID — not reloading. Backup is in /etc/caddy/Caddyfile.pre-vibescan.*"
  exit 1
fi
CADDYEOF
else
  run scp deploy/Caddyfile.vibescan "$TARGET:/tmp/vibescan.caddy"
  echo "   [dry] would append/replace the managed $DOMAIN block and reload"
fi

say "Verify"
run ssh "$TARGET" 'curl -sS -m 5 -o /dev/null -w "local health: %{http_code}\n" http://127.0.0.1:4200/api/health'
run ssh "$TARGET" "curl -sS -m 5 -o /dev/null -w \"via caddy:   %{http_code}\n\" -H \"Host: $DOMAIN\" http://127.0.0.1/api/health"

if [ "$APPLY" = 0 ]; then
  echo
  echo "Dry run. Nothing changed. Re-run with --apply."
fi
