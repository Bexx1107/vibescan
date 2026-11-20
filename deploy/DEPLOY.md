# Deploying VibeScan

Two processes, one host, one SQLite file. The public process can read and write public scores; the admin process binds to a private tailnet interface and is the only process that can moderate entries. Keeping them separate avoids exposing admin routes on the public origin.

```
internet ──► Caddy :443 ──► 127.0.0.1:4200 ──► public process (vibescan user)
tailnet  ──────────────────────────────────► tailnet_ip:4201 ──► admin (vibescan user)
```

## One-time DNS (before TLS can issue)

Caddy obtains a TLS certificate after DNS resolves publicly:

1. Point your domain's `A @` and `A www` records at your server's public IP (for example `203.0.113.10`).
2. Confirm propagation before deploying:

```bash
dig +short NS your-domain.example @1.1.1.1
dig +short A  your-domain.example @1.1.1.1
```

## Deploy

```bash
VIBESCAN_DOMAIN=your-domain.example ./deploy/deploy.sh root@203.0.113.10          # dry run
VIBESCAN_DOMAIN=your-domain.example ./deploy/deploy.sh root@203.0.113.10 --apply  # apply
```

The script is idempotent. On redeploy it replaces the managed Caddy block in place rather than appending a second copy, and validates the Caddyfile before reloading.

## Public process environment

`deploy/public.env.example` is the template:
- `VIBESCAN_PUBLIC=1` — enables the public leaderboard, forces passive-only scans (`skipActive: true`), and enforces per-IP rate limits.
- `HOST=127.0.0.1` — loopback bind behind Caddy.
- `VIBESCAN_TOKEN` — protects internal `/api/jobs` and `/api/report` routes even if `HOST` is changed later.

Never set `VIBESCAN_ALLOW_INSECURE=1` on a public host.

## Client IP and rate limits

The rate limiter keys on `sha256(ip + per-day random salt)`. It trusts `X-Real-IP` set by Caddy (`header_up X-Real-IP {remote_host}`) and ignores `X-Forwarded-For`, which is verified by `test/ip.test.js`.

## Verifying a deploy

```bash
ssh root@203.0.113.10 'curl -sS http://127.0.0.1:4200/api/health'
curl -sS https://your-domain.example/api/health
curl -sS https://your-domain.example/api/leaderboard/stats
```

## Reverse-proxy CDN note (optional Cloudflare)

If you place Cloudflare in front later:
1. Configure `trusted_proxies` in your Caddy global block with Cloudflare IP ranges so `{client_ip}` resolves from `CF-Connecting-IP`.
2. Update `lib/leaderboard.js` `trustedIp()` and `test/ip.test.js` to accept `cf-connecting-ip` ahead of `x-real-ip`.
3. Update `deploy/Caddyfile.vibescan` to forward `header_up X-Real-IP {client_ip}`.
4. Set Cloudflare SSL/TLS mode to **Full (strict)** to avoid redirect loops with Caddy.

## Rollback

```bash
ssh root@203.0.113.10 'cp /etc/caddy/Caddyfile.pre-vibescan.<ts> /etc/caddy/Caddyfile \
  && caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
  && systemctl reload caddy'
systemctl stop vibescan-public && systemctl disable vibescan-public
```

The SQLite database at `/home/vibescan/app/data/vibescan.db` is untouched by rollback.
