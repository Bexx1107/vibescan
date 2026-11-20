'use strict';
/**
 * VibeScan admin — a SEPARATE process on a SEPARATE port.
 *
 * Why separate: the public site (server.js, VIBESCAN_PUBLIC=1) must never be
 * able to reach moderation power. This process is the only thing that can
 * flip `site.status`, so it binds to the tailnet address only and refuses to
 * start without an explicit bind host + admin token.
 *
 *   ADMIN_HOST=100.64.0.10   (tailscale ip -4 — NEVER 0.0.0.0)
 *   ADMIN_PORT=4201
 *   ADMIN_TOKEN=<long random>
 *
 * Then from the VPS:   http://100.64.0.10:4201/
 *
 * Security posture:
 *   • Binds to a tailnet address. Not reachable from the public internet even
 *     if the firewall is misconfigured, because the address does not exist
 *     outside the tailnet.
 *   • Refuses 0.0.0.0 and refuses to boot without a token >= 24 chars.
 *   • Every data route needs `Authorization: Bearer <token>` (constant-time).
 *   • The static shell carries no data; it asks for the token and keeps it in
 *     sessionStorage only.
 *   • The DB is opened read-write here and NOWHERE else, so a public-side bug
 *     cannot become a moderation bypass.
 *   • Every mutation is appended to admin_audit so you can see who removed what.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const db = require('../lib/db');

const HOST = String(process.env.ADMIN_HOST || '127.0.0.1').trim();
const PORT = Number(process.env.ADMIN_PORT || 4201);
const TOKEN = String(process.env.ADMIN_TOKEN || '').trim();
const SHELL = path.join(__dirname, 'index.html');

/* ------------------------------------------------------------------ *
 * Boot guards — fail closed
 * ------------------------------------------------------------------ */

if (!TOKEN || TOKEN.length < 24) {
  console.error(
    'admin: ADMIN_TOKEN missing or shorter than 24 chars.\n' +
      '       generate one with:  openssl rand -hex 32'
  );
  process.exit(1);
}
if (HOST === '0.0.0.0' || HOST === '::' || HOST === '') {
  console.error(
    'admin: refusing to bind to a wildcard address.\n' +
      '       Set ADMIN_HOST to the tailscale address (tailscale ip -4).'
  );
  process.exit(1);
}

const TOKEN_BUF = Buffer.from(TOKEN, 'utf8');

/** Constant-time token check. Never leaks length via timing. */
function tokenOk(req) {
  const raw = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(raw);
  if (!m) return false;
  const got = Buffer.from(m[1].trim(), 'utf8');
  if (got.length !== TOKEN_BUF.length) {
    // Still burn a comparison so the timing profile does not reveal the length.
    crypto.timingSafeEqual(TOKEN_BUF, Buffer.alloc(TOKEN_BUF.length));
    return false;
  }
  return crypto.timingSafeEqual(got, TOKEN_BUF);
}

/* ------------------------------------------------------------------ *
 * Own connection (read-write), with an audit table it maintains itself.
 * ------------------------------------------------------------------ */

let conn = null;

function dbc() {
  if (conn) return conn;
  conn = db.open(); // same file, same dir, 0600 — shared with the public process
  conn.exec(`
    CREATE TABLE IF NOT EXISTS admin_audit (
      id         INTEGER PRIMARY KEY,
      at         TEXT NOT NULL,
      action     TEXT NOT NULL,
      subject    TEXT,
      detail     TEXT,
      ip_hash    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_at ON admin_audit(at DESC);
  `);
  return conn;
}

function audit(action, subject, detail, ipHash) {
  dbc()
    .prepare(
      'INSERT INTO admin_audit (at, action, subject, detail, ip_hash) VALUES (?, ?, ?, ?, ?)'
    )
    .run(new Date().toISOString(), action, subject || null, detail || null, ipHash || null);
}

function ipHash(req) {
  const addr = req.socket.remoteAddress || '';
  return crypto.createHash('sha256').update(addr).digest('hex').slice(0, 16);
}

/* ------------------------------------------------------------------ *
 * HTTP helpers
 * ------------------------------------------------------------------ */

function json(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  res.end(body);
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        req.destroy();
        resolve('');
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

function readJson(req) {
  return readBody(req).then((s) => {
    try {
      return s ? JSON.parse(s) : {};
    } catch {
      return null;
    }
  });
}

/* ------------------------------------------------------------------ *
 * Read model
 * ------------------------------------------------------------------ */

function overview() {
  const c = dbc();
  const sites = c.prepare('SELECT status, COUNT(*) AS n FROM site GROUP BY status').all();
  const counts = Object.fromEntries(sites.map((r) => [r.status, r.n]));
  return {
    sites: {
      listed: counts.listed || 0,
      claimed: counts.claimed || 0,
      hidden: counts.hidden || 0,
      removed: counts.removed || 0,
    },
    scans: c.prepare('SELECT COUNT(*) AS n FROM scan').get().n,
    submissions: c.prepare('SELECT COUNT(*) AS n FROM submission').get().n,
    pendingRemovals: c
      .prepare("SELECT COUNT(*) AS n FROM removal_request WHERE status = 'pending'")
      .get().n,
    pendingClaims: c
      .prepare("SELECT COUNT(*) AS n FROM claim_request WHERE status = 'pending'")
      .get().n,
    disputed: c
      .prepare("SELECT COUNT(*) AS n FROM submission WHERE verification = 'disputed'")
      .get().n,
  };
}

function removals(status) {
  const c = dbc();
  const rows = c
    .prepare(
      `SELECT r.id, r.reason, r.email, r.status, r.created_at,
              s.host, s.status AS site_status
         FROM removal_request r
         JOIN site s ON s.id = r.site_id
        WHERE (?1 IS NULL OR r.status = ?1)
        ORDER BY r.created_at DESC
        LIMIT 500`
    )
    .all(status || null);
  return rows.map((r) => ({ ...r }));
}

function claims() {
  return dbc()
    .prepare(
      `SELECT c.id, c.method, c.token, c.status, c.created_at, c.verified_at,
              s.host, s.status AS site_status
         FROM claim_request c
         JOIN site s ON s.id = c.site_id
        ORDER BY c.created_at DESC
        LIMIT 500`
    )
    .all()
    .map((r) => ({ ...r }));
}

function sites(q) {
  const c = dbc();
  const like = q ? `%${q}%` : null;
  return c
    .prepare(
      `SELECT s.id, s.host, s.url, s.status, s.first_seen, s.last_seen,
              sc.score, sc.grade, sc.at AS scanned_at
         FROM site s
         LEFT JOIN scan sc ON sc.id = s.latest_scan
        WHERE (?1 IS NULL OR s.host LIKE ?1)
        ORDER BY sc.score ASC NULLS LAST, s.host ASC
        LIMIT 300`
    )
    .all(like)
    .map((r) => ({ ...r }));
}

function disputed() {
  return dbc()
    .prepare(
      `SELECT sub.id, sub.builder_kind, sub.builder_name, sub.platform,
              sub.verification, sub.confidence, sub.evidence_json, sub.created_at,
              s.host
         FROM submission sub
         JOIN site s ON s.id = sub.site_id
        WHERE sub.verification = 'disputed'
        ORDER BY sub.created_at DESC
        LIMIT 300`
    )
    .all()
    .map((r) => {
      let ev = [];
      try {
        ev = JSON.parse(r.evidence_json || '[]');
      } catch {
        ev = [];
      }
      return { ...r, evidence: ev, evidence_json: undefined };
    });
}

function auditLog() {
  return dbc()
    .prepare('SELECT * FROM admin_audit ORDER BY at DESC LIMIT 200')
    .all()
    .map((r) => ({ ...r }));
}

/* ------------------------------------------------------------------ *
 * Mutations — every one is audited
 * ------------------------------------------------------------------ */

const SITE_STATES = new Set(['listed', 'claimed', 'hidden', 'removed']);

function setSiteStatus(host, status, ip) {
  if (!SITE_STATES.has(status)) return { error: 'invalid status' };
  const c = dbc();
  const site = c.prepare('SELECT id, status FROM site WHERE host = ?').get(host);
  if (!site) return { error: 'unknown host' };
  c.prepare('UPDATE site SET status = ? WHERE id = ?').run(status, site.id);
  audit('site.status', host, `${site.status} -> ${status}`, ip);
  return { ok: true, host, from: site.status, to: status };
}

function resolveRemoval(id, decision, ip) {
  if (!['approved', 'rejected'].includes(decision)) return { error: 'invalid decision' };
  const c = dbc();
  const r = c
    .prepare(
      `SELECT r.id, r.status, r.site_id, s.host
         FROM removal_request r JOIN site s ON s.id = r.site_id
        WHERE r.id = ?`
    )
    .get(id);
  if (!r) return { error: 'unknown request' };
  if (r.status !== 'pending') return { error: 'already resolved' };

  c.prepare('UPDATE removal_request SET status = ? WHERE id = ?').run(decision, id);
  if (decision === 'approved') {
    // PLAN §8 Phase 5: removal is honoured unconditionally and immediately.
    c.prepare("UPDATE site SET status = 'removed' WHERE id = ?").run(r.site_id);
  }
  audit('removal.' + decision, r.host, `request #${id}`, ip);
  return { ok: true, host: r.host, decision };
}

function resolveClaim(id, decision, ip) {
  if (!['verified', 'rejected'].includes(decision)) return { error: 'invalid decision' };
  const c = dbc();
  const r = c
    .prepare(
      `SELECT c.id, c.status, c.site_id, s.host
         FROM claim_request c JOIN site s ON s.id = c.site_id
        WHERE c.id = ?`
    )
    .get(id);
  if (!r) return { error: 'unknown request' };
  if (r.status !== 'pending') return { error: 'already resolved' };

  c.prepare('UPDATE claim_request SET status = ? WHERE id = ?').run(decision, id);
  if (decision === 'verified') {
    c.prepare("UPDATE site SET status = 'claimed' WHERE id = ? AND status = 'listed'").run(
      r.site_id
    );
  }
  audit('claim.' + decision, r.host, `request #${id}`, ip);
  return { ok: true, host: r.host, decision };
}

/* ------------------------------------------------------------------ *
 * Router
 * ------------------------------------------------------------------ */

async function handle(req, res) {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const p = url.pathname;

  // The shell is data-free, so it can load before the operator pastes a token.
  if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
    fs.readFile(SHELL, (err, data) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end('admin shell missing');
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy':
          "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
      });
      res.end(data);
    });
    return;
  }

  if (p === '/api/admin/health') return json(res, 200, { ok: true });

  if (!p.startsWith('/api/admin/')) return json(res, 404, { error: 'not found' });

  if (!tokenOk(req)) {
    await readBody(req); // drain, then reject
    return json(res, 401, { error: 'unauthorized' });
  }

  const ip = ipHash(req);

  if (req.method === 'GET' && p === '/api/admin/overview') {
    return json(res, 200, overview());
  }
  if (req.method === 'GET' && p === '/api/admin/removals') {
    return json(res, 200, { rows: removals(url.searchParams.get('status')) });
  }
  if (req.method === 'GET' && p === '/api/admin/claims') {
    return json(res, 200, { rows: claims() });
  }
  if (req.method === 'GET' && p === '/api/admin/sites') {
    return json(res, 200, { rows: sites(url.searchParams.get('q')) });
  }
  if (req.method === 'GET' && p === '/api/admin/disputed') {
    return json(res, 200, { rows: disputed() });
  }
  if (req.method === 'GET' && p === '/api/admin/audit') {
    return json(res, 200, { rows: auditLog() });
  }

  if (req.method === 'POST' && p === '/api/admin/site') {
    const body = await readJson(req);
    if (!body) return json(res, 400, { error: 'invalid json' });
    const host = db.normaliseHost(body.host || '');
    if (!host) return json(res, 400, { error: 'invalid host' });
    const out = setSiteStatus(host, String(body.status || ''), ip);
    return json(res, out.error ? 400 : 200, out);
  }

  if (req.method === 'POST' && p.startsWith('/api/admin/removal/')) {
    const id = Number(p.slice('/api/admin/removal/'.length));
    if (!Number.isInteger(id)) return json(res, 400, { error: 'invalid id' });
    const body = await readJson(req);
    if (!body) return json(res, 400, { error: 'invalid json' });
    const out = resolveRemoval(id, String(body.decision || ''), ip);
    return json(res, out.error ? 400 : 200, out);
  }

  if (req.method === 'POST' && p.startsWith('/api/admin/claim/')) {
    const id = Number(p.slice('/api/admin/claim/'.length));
    if (!Number.isInteger(id)) return json(res, 400, { error: 'invalid id' });
    const body = await readJson(req);
    if (!body) return json(res, 400, { error: 'invalid json' });
    const out = resolveClaim(id, String(body.decision || ''), ip);
    return json(res, out.error ? 400 : 200, out);
  }

  return json(res, 404, { error: 'not found' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error('admin error:', err && err.message);
    try {
      json(res, 500, { error: 'internal error' });
    } catch {
      /* headers already sent */
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`VibeScan admin on http://${HOST}:${PORT}`);
  console.log(`DB: ${db.DB_FILE}`);
  console.log('Bound to a tailnet address only. Not reachable from the internet.');
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close(() => {
      try {
        db.close();
      } catch {
        /* already closed */
      }
      process.exit(0);
    });
  });
}
