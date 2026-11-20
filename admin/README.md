# VibeScan admin — separate process, private network only

A minimal, auth-gated moderation service built as its own process on its own port, bound to a private tailnet/WireGuard interface rather than the public internet.

It is not part of `server.js`: the public server loads no moderation code and exposes no route that can mutate `site.status`.

---

## 1. Separation model

| Concern | Public (`server.js`) | Admin (`admin/server.js`) |
| --- | --- | --- |
| Bind | `127.0.0.1` behind reverse proxy | Private tailnet IP (`100.64.0.10`) |
| Reachable from internet | Yes (via Caddy) | No |
| Routes mutating `site.status` | None | All moderation endpoints |
| Token | Optional for internal routes | Mandatory, >= 24 chars, no bypass |
| Static shell | Public UI | Single HTML file, CSP `default-src 'none'` |
| Audit trail | — | Every mutation logged to `admin_audit` |

Both processes open `data/vibescan.db` in SQLite WAL mode.

---

## 2. Configuration

Generate a dedicated token (do not reuse `VIBESCAN_TOKEN`):

```bash
openssl rand -hex 32
```

Create a separate env file (for example `/etc/vibescan/admin.env`, mode `0600`):

```bash
ADMIN_HOST=100.64.0.10
ADMIN_PORT=4201
ADMIN_TOKEN=<paste-token-here>
VIBESCAN_DB_DIR=/home/vibescan/app/data
```

---

## 3. Running

```bash
npm run admin          # or: node admin/server.js
```

The server refuses to start if `ADMIN_TOKEN` is missing or shorter than 24 characters, or if `ADMIN_HOST` is empty or wildcard (`0.0.0.0`, `::`).

### systemd

```bash
sudo cp deploy/vibescan-admin.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vibescan-admin
sudo systemctl status vibescan-admin
```

Access via the tailnet IP or SSH port forwarding (`ssh -L 4201:127.0.0.1:4201 user@host`).

---

## 4. Tabs

| Tab | Purpose |
| --- | --- |
| **Overview** | Site counts by status, scans, submissions, pending queues |
| **Removals** | Pending removal requests -> Approve (`removed`) or Reject |
| **Claims** | Ownership requests with attempted verification method |
| **Disputed** | Submissions where checks contradicted the builder claim |
| **Sites** | Search and manually set status (`listed`, `claimed`, `hidden`, `removed`) |
| **Audit** | Recent 200 mutations with timestamp, action, host, hashed IP |

---

## 5. API (requires `Authorization: Bearer <token>`)

```
GET  /api/admin/health              no auth — liveness only
GET  /api/admin/overview
GET  /api/admin/removals[?status=pending]
GET  /api/admin/claims
GET  /api/admin/disputed
GET  /api/admin/sites[?q=host]
GET  /api/admin/audit

POST /api/admin/site                {"host":"example.com","status":"listed|claimed|hidden|removed"}
POST /api/admin/removal/:id         {"decision":"approved|rejected"}
POST /api/admin/claim/:id           {"decision":"verified|rejected"}
```
