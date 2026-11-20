# VibeScan

A self-hosted web checker and optional public leaderboard built with Node.js (`>= 22.5`, built-in `node:sqlite`) and zero third-party npm dependencies. Built as a personal side project with AI assistance.

It checks public websites across six categories — Security, Privacy/GDPR, Performance (CWV lab), Accessibility, SEO, and Code Hygiene — and gives each domain a 0–100 score.

## Modes: Public vs Local

Make sure you understand the difference between the two modes before exposing an instance:

- **Public mode (`VIBESCAN_PUBLIC=1`):**
  - Strictly **passive** (`skipActive: true` enforced in both `lib/scanner.js` and `lib/leaderboard.js`): fetches normal pages, HTTP headers, TLS handshake info, DNS records (`SPF`/`DMARC`/`CAA`/`DNSSEC`), public JS bundles, `robots.txt`/`sitemap.xml`/`llms.txt`, and passive Shodan InternetDB lookups. Active probing (`/.env`, `/.git/HEAD`, reflected XSS/redirect fuzzing, `Host:` spoofing) and `nuclei` are disabled.
  - Full findings stay in RAM for 10 minutes (`ephemeralReports` in `lib/queue.js`) and are never written to disk; SQLite only stores numeric 0–100 scores, tech hints, and user-submitted claims (or nothing if the submitter checks **Hide Results**).
- **Local / internal mode (`VIBESCAN_PUBLIC=0`, default):**
  - Meant for auditing **your own** domains or local repositories (`POST /api/audit/local`).
  - Runs the read-only active-but-safe probe suite in `lib/probes.js` (`checkPathExposure`, `/.env`, `/.git/HEAD`, open redirects, unescaped query reflections, `Host:` header reflection, GraphQL introspection, CORS/debug endpoints) and optionally wraps `nuclei` if you pass `{ pentest: true }`.
  - Saves full reports to `data/reports/`.

## What It Actually Checks (and Limitations)

This is a heuristic checker built on Node.js built-ins + regex/string rules + optional headless Chromium. **It does not replace SSL Labs, Google Lighthouse, Deque axe-core, or a manual security audit.**

- **Scoring math:** Per-domain scores use simple severity deductions (`100 - sum(penalty)` per domain), averaged across the six domains and capped at `88` (1 high finding), `82` (2–3 high), `74` (4+ high), or `69` (any critical finding). This is an opinionated heuristic, not a Lighthouse log-normal curve.
- **Security:** TLS cipher/protocol checks, security headers, cookie flags, DNS records, SRI coverage on external `<script>` tags, regex secret patterns in public JS bundles, CT subdomain lookup, and Shodan InternetDB. When `VIBESCAN_PUBLIC=0`, `lib/probes.js` also sends ~70 read-only `GET`/`HEAD`/`OPTIONS` probe requests.
- **Privacy / GDPR:** Inspects `Set-Cookie` and third-party requests fired on initial page load before consent, looks for common CMP banners, maps third-party host regions, and checks for privacy/terms/imprint links. It cannot click through multi-step consent flows or verify server-side compliance.
- **Performance (CWV lab):** Requires local Chromium/Chrome. Injects a `PerformanceObserver` script over raw CDP to capture lab LCP, CLS, TBT (as a proxy for INP), FCP, TTFB, payload size, and compression. Without Chromium, scans still complete as `degraded` with scores capped.
- **Accessibility:** Custom static HTML regex checks plus post-JS DOM + computed color-contrast evaluation in Chromium. Useful for catching missing form labels, alt text, and contrast failures; it is *not* `axe-core` and does not cover full WCAG 2.2 manual criteria.
- **SEO & Code Hygiene:** Titles, meta descriptions, canonical tags, OpenGraph, JSON-LD parsing, `robots.txt` AI-bot rules, `sitemap.xml`, `llms.txt`, render-blocking scripts, broken links, and HTML weight.
- **WAFs & SPAs:** Aggressive WAF challenges (403/429/bot checkpoints) or client-heavy SPAs can limit what passive fetches observe; `FIRECRAWL_API_KEY` and `PAGESPEED_API_KEY` are strictly optional.
- **Authorization:** Only run local active mode (`VIBESCAN_PUBLIC=0`) against domains you own or have permission to scan.

## Requirements

- **Node.js `>= 22.5`** (uses built-in `node:sqlite` and global `WebSocket`)
- **Optional:** Chromium / Chrome in `PATH` (for headless DOM rendering, CWV lab metrics, and computed color contrast)
- **Optional:** `nuclei` binary (for authorized local `pentest` profile only; never runs in public mode)

## Quick Start

```bash
cp .env.example .env
node server.js
# Listening on http://127.0.0.1:4200
```

To expose beyond localhost (e.g. `HOST=0.0.0.0`), generate a token first (`./make-token.sh` or set `VIBESCAN_TOKEN` in `.env`) — `server.js` refuses non-loopback binds without auth unless `VIBESCAN_ALLOW_INSECURE=1`.

Run tests and checks:

```bash
npm test
node tools/check_cover.js
npm run smoke
```

## Architecture Overview

- **Zero npm dependencies:** uses only Node.js built-ins (`http`, `https`, `tls`, `dns`, `net`, `crypto`, `child_process`, `node:sqlite`).
- **Worker process isolation (`lib/queue.js` + `lib/scan-worker.js`):** each queued scan runs in a detached forked child process (`--max-old-space-size=512`, `VIBESCAN_CONCURRENCY=2`) with a hard process-group `SIGKILL` timeout (`VIBESCAN_JOB_TIMEOUT_MS=120000`), in-flight URL deduplication, and bounded queue length (`VIBESCAN_MAX_QUEUED=25`).
- **Privilege-separated admin service (`admin/server.js`):** separate local/tailnet process for moderation (`npm run admin`); see [`admin/README.md`](admin/README.md).
- **Deployment templates:** systemd units, Caddyfile, and deploy script live in [`deploy/`](deploy/DEPLOY.md).

## Configuration

See [`.env.example`](.env.example):

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Bind address (`0.0.0.0` requires `VIBESCAN_TOKEN` unless `VIBESCAN_ALLOW_INSECURE=1`) |
| `PORT` | `4200` | HTTP port |
| `VIBESCAN_PUBLIC` | `0` | Enables public leaderboard UI (`board.html`), rate limits, and forces `skipActive: true` |
| `VIBESCAN_TOKEN` | — | Bearer token protecting internal `/api/*` routes |
| `VIBESCAN_CONCURRENCY` | `2` | Concurrent scan worker processes (1–4) |
| `VIBESCAN_JOB_TIMEOUT_MS` | `120000` | Hard per-scan process-group timeout (ms) |
| `VIBESCAN_MAX_QUEUED` | `25` | Max pending queue depth before returning HTTP `503` |
| `PUBLIC_BASE_URL` | — | Canonical base URL for metadata and self-favicon lookup |
| `SCANNER_EGRESS` | — | Optional ordered HTTP egress proxy list (`vpn=...,res=...`) |
| `SCANNER_ALLOW_DIRECT` | `0` | Allow direct fallback when `SCANNER_EGRESS` is set |
| `FIRECRAWL_API_KEY` | — | Optional Firecrawl API key for anti-bot/SPA fallback rendering |

## License

[MIT](LICENSE)
