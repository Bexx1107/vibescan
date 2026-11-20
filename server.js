'use strict';
/**
 * VibeScan server — internal tool, zero external dependencies.
 *
 *   GET  /                          → UI (public/index.html)
 *   POST /api/scan                  → { url } → full JSON report (sync, persists + diff)
 *   POST /api/scan/async            → { url } → { job } (queued, non-blocking)
 *   GET  /api/jobs                  → recent jobs
 *   GET  /api/jobs/:id              → one job (status + diff)
 *   GET  /api/health                → { ok, lastScan, queue }
 *   GET  /api/history[?target=]     → persisted scan summaries (newest first)
 *   GET  /api/report/:id            → full stored report
 *   GET  /api/report/:id/diff       → diff vs the previous scan of the same target
 *   GET  /api/export/:id.(json|md|html|sarif) → download a report
 *
 * Reports persist across restarts (lib/store.js); long scans can be offloaded
 * to the background job queue (lib/queue.js) so the HTTP server stays free.
 */

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { URL } = require('url');
const { scan } = require('./lib/scanner');
const store = require('./lib/store');
const queue = require('./lib/queue');
const { diffReports } = require('./lib/diff');
const exporters = require('./lib/export');
const integrity = require('./lib/integrity');
const { runLocalSourceAudit } = require('./lib/local-audit');
const nuclei = require('./lib/nuclei');
const db = require('./lib/db');                    // leaderboard store (node:sqlite)
const leaderboard = require('./lib/leaderboard');  // leaderboard HTTP layer
const favicon = require('./lib/favicon');          // favicon cache & proxy

// Automatically load .env if present
try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    for (const l of lines) {
      const trimmed = l.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
      if (idx !== -1) {
        const k = trimmed.slice(0, idx).trim();
        const v = trimmed.slice(idx + 1).trim();
        if (!process.env[k]) process.env[k] = v;
      }
    }
  }
} catch (e) {}

const PORT = process.env.PORT || 4200;

// P0 — access control. Stored reports contain discovered secrets and PII in
// full, un-redacted form, so every endpoint is a credential dump
// if it is reachable by anyone else. "Local tool" and "0.0.0.0" are not the
// same thing: binding all interfaces put those reports on the LAN/Tailscale.
//
//   • Default bind is now loopback (127.0.0.1).
//   • To expose it (e.g. HOST=0.0.0.0) you MUST set VIBESCAN_TOKEN; the server
//     refuses to start otherwise rather than silently leaking.
//   • When a token is set, every /api/* route except /api/health requires
//     `Authorization: Bearer <token>` (or `?token=`).
//
// A HOST name is not an identity. Binding 0.0.0.0 behind Tailscale/NAT/proxy
// means the TCP peer of every request is just your own machine or the proxy —
// so "the request came from loopback" proves nothing about *who* sent it. Auth
// therefore keys off the token alone (plus the explicit ALLOW_INSECURE opt-out).
const HOST = process.env.HOST || '127.0.0.1';
const API_TOKEN = (process.env.VIBESCAN_TOKEN || '').trim();

// Escape hatch, at the operator's explicit request. Set VIBESCAN_ALLOW_INSECURE=1
// to run a non-loopback bind with NO auth at all. This is genuinely dangerous —
// every stored report (un-redacted secrets + PII) becomes readable and anyone on
// the network can trigger scans — so it must be typed out on purpose and the
// server screams about it on every start. Prefer VIBESCAN_TOKEN unless you
// consciously accept that risk (e.g. a throwaway instance on a trusted LAN).
const ALLOW_INSECURE = process.env.VIBESCAN_ALLOW_INSECURE === '1';

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
const BINDS_PUBLICLY = !LOOPBACK.has(HOST) && HOST !== '::ffff:127.0.0.1';

const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY = 16 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
};

// Decode a URL path segment without ever throwing. A malformed percent-escape
// (e.g. GET /api/report/%E0%A4%A) used to raise an uncaught URIError inside the
// async request handler and take the whole server down — one request = full DoS.
function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

// Report/job ids are generated locally as `<timestamp>-<rand>`; anything that is
// not strictly [A-Za-z0-9._-] (notably `..` and `/`) is rejected so a crafted id
// can never escape the reports directory via path.join().
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/;
function validId(id) {
  return typeof id === 'string' && ID_RE.test(id) && !id.includes('..');
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

function sendText(res, code, body, type, filename) {
  const headers = { 'Content-Type': type + '; charset=utf-8', 'Cache-Control': 'no-store' };
  if (filename) headers['Content-Disposition'] = `attachment; filename="${filename}"`;
  res.writeHead(code, headers);
  res.end(body);
}

// Auth-aware scanning: allow only a small, safe set of request headers so a
// caller can authenticate to a private/staging site. Deliberately excludes
// Host (would break SSRF/redirect validation) and anything hop-by-hop.
const ALLOWED_AUTH_HEADERS = new Set([
  'authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-forwarded-for',
  'referer', 'origin', 'accept-language',
]);

function sanitizeHeaders(input) {
  if (!input || typeof input !== 'object') return null;
  const out = {};
  for (const [k, v] of Object.entries(input)) {
    if (ALLOWED_AUTH_HEADERS.has(String(k).toLowerCase()) && typeof v === 'string' && v.length <= 4096) {
      out[k] = v;
    }
  }
  return Object.keys(out).length ? out : null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function serveStatic(res, urlPath) {
  const isPublic = process.env.VIBESCAN_PUBLIC === '1';

  // The public leaderboard lives at /board.html; expose it at /leaderboard too
  // so it can be linked without a file extension.
  if (urlPath === '/leaderboard' || urlPath === '/leaderboard/') urlPath = '/board.html';

  // On the public instance, root and /index.html serve the public leaderboard.
  if (isPublic && (urlPath === '/' || urlPath === '/index.html')) {
    urlPath = '/board.html';
  }

  // Developer access to internal scanner UI if requested explicitly
  if (urlPath === '/scanner' || urlPath === '/scanner.html') {
    urlPath = '/index.html';
  }

  const safe = urlPath === '/' ? '/index.html' : urlPath;
  const abs = path.join(PUBLIC_DIR, path.normalize(safe).replace(/^(\.\.[/\\])+/, ''));
  if (!abs.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(abs, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const ext = path.extname(abs);
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream' };
    if (['.js', '.css'].includes(ext)) {
      headers['Cache-Control'] = 'no-cache, no-store, must-revalidate';
    } else if (['.png', '.webp', '.svg', '.woff2', '.ico', '.jpg', '.jpeg'].includes(ext)) {
      headers['Cache-Control'] = 'public, max-age=86400, stale-while-revalidate=3600';
    } else if (ext === '.html') {
      headers['Cache-Control'] = 'public, max-age=0, must-revalidate';
    }
    res.writeHead(200, headers);
    res.end(data);
  });
}

/** Run a scan, persist it, and attach the diff vs the previous scan. */
async function runAndStore(url, scanOptions = {}) {
  const report = await scan(url, scanOptions);

  if (scanOptions.pentest || scanOptions.profile === 'pentest') {
    try {
      const nRes = await nuclei.runNucleiScan(report.finalUrl || url, {
        severity: scanOptions.nucleiSeverity || 'critical,high,medium,low',
        tags: scanOptions.nucleiTags,
        maxTime: '2m',
      });
      if (nRes && nRes.findings && nRes.findings.length) {
        report.findings.push(...nRes.findings);
        report.counts = {
          critical: report.findings.filter((f) => f.severity === 'critical').length,
          high: report.findings.filter((f) => f.severity === 'high').length,
          medium: report.findings.filter((f) => f.severity === 'medium').length,
          low: report.findings.filter((f) => f.severity === 'low').length,
          info: report.findings.filter((f) => f.severity === 'info').length,
        };
        const penalty = report.counts.critical * 30 + report.counts.high * 15 + report.counts.medium * 5;
        report.score = Math.max(0, Math.min(100, report.score - penalty));
        report.grade = report.score >= 90 ? 'A' : report.score >= 80 ? 'B' : report.score >= 70 ? 'C' : report.score >= 55 ? 'D' : 'F';
        if (report.domains && report.domains.security) {
          report.domains.security.score = Math.max(0, Math.min(100, report.domains.security.score - penalty));
          report.domains.security.grade = report.grade;
          report.domains.security.total = report.findings.filter((f) => f.domain === 'security').length;
        }
      }
      report.durationMs = (report.durationMs || 0) + (nRes.durationMs || 0);
      report.meta = report.meta || {};
      report.meta.nuclei = {
        enabled: true,
        durationMs: nRes.durationMs,
        findingsCount: nRes.findings ? nRes.findings.length : 0,
      };
    } catch (err) {
      console.error('[nuclei] integration error:', err.message);
    }
  }

  const meta = store.saveReport(report);
  const { previous } = store.lastTwoFor(report.finalUrl || report.target);
  const diff = previous ? diffReports(previous, report) : diffReports(null, report);
  report.id = meta.id;
  report.targetKey = meta.targetKey;
  report.diff = diff;

  // Mirror the scan into the leaderboard DB (derived fields only — the full
  // report stays in the JSON store). A DB failure must never fail a scan that
  // has already been paid for.
  try {
    db.recordScan(report, { reportId: meta.id, deep: scanOptions.deep !== false });
  } catch (err) {
    console.error('[leaderboard] recordScan failed:', err.message);
  }

  return report;
}

// Wrap every request so a throw (or rejected promise) produces a clean 500
// instead of an unhandled rejection / process crash. The handler is invoked
// synchronously so a synchronous throw also lands in the catch.
const server = http.createServer((req, res) => {
  Promise.resolve()
    .then(() => handleRequest(req, res))
    .catch((err) => {
      console.error('[vibescan] request failed:', err && err.stack ? err.stack : err);
      if (!res.headersSent) {
        try { sendJson(res, 500, { error: 'Internal server error' }); }
        catch { try { res.end(); } catch { /* socket already gone */ } }
      } else {
        try { res.end(); } catch { /* ignore */ }
      }
    });
});

/**
 * Constant-time string compare (avoids leaking token length/prefix by timing).
 * Both inputs are hashed to a fixed width first so lengths never differ.
 */
function safeEqual(a, b) {
  const crypto = require('crypto');
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/**
 * P0 access gate. Returns true when the request may proceed.
 *
 * Public (no token needed): GET /api/health, and all static assets — the UI
 * itself holds no secrets and needs to load in order to *ask* for a token.
 * Everything else under /api/* is refused without the token.
 */
function authorized(req, pathname, q) {
  if (ALLOW_INSECURE) return true;                   // explicit operator opt-out
  if (!API_TOKEN) return true;                       // loopback-only default
  if (pathname === '/api/health') return true;       // liveness, no report data
  if (pathname.startsWith('/api/favicon')) return true; // Favicon public cache endpoint
  if (!pathname.startsWith('/api/')) return true;    // static UI shell

  // Leaderboard surface: the token gates the INTERNAL scanner, not the public
  // leaderboard. In public mode (VIBESCAN_PUBLIC=1) the whole leaderboard — reads AND writes — is open,
  // because "anyone can submit, any time" was an explicit operator decision;
  // writes are protected by the per-IP rate limits in lib/leaderboard.js.
  //
  // Without VIBESCAN_PUBLIC, only reads are open and every write needs the
  // token, so an accidentally exposed internal instance cannot be written to.
  //
  // Either way the leaderboard never serves full reports: only the public-safe
  // projection in lib/leaderboard.js, which strips meta/evidence/detail.
  if (pathname.startsWith('/api/leaderboard')) {
    const isPublic = process.env.VIBESCAN_PUBLIC === '1';
    if (isPublic) return true;
    if (req.method.toUpperCase() === 'GET') return true;
  }

  const hdr = req.headers['authorization'] || '';
  const bearer = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  const supplied = bearer || q.get('token') || '';
  return supplied.length > 0 && safeEqual(supplied, API_TOKEN);
}

async function handleRequest(req, res) {
  let parsed;
  try {
    parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch {
    return sendJson(res, 400, { error: 'Bad request URL' });
  }
  const pathname = parsed.pathname;
  const q = parsed.searchParams;

  if (!authorized(req, pathname, q)) {
    res.setHeader('WWW-Authenticate', 'Bearer realm="vibescan"');
    return sendJson(res, 401, { error: 'Unauthorized', hint: 'Send Authorization: Bearer <VIBESCAN_TOKEN>' });
  }

  // Favicon caching endpoint: GET /api/favicon/:host or GET /api/favicon?host=...
  if (req.method === 'GET' && (pathname.startsWith('/api/favicon/') || pathname === '/api/favicon')) {
    return favicon.serveFavicon(req, res, pathname, q);
  }

  // Leaderboard routes: handled before the generic /api routes;
  // returns false for any path it does not own.
  if (await leaderboard.handle(req, res, { pathname, q, sendJson, readBody, queue, store })) {
    return;
  }

  if (req.method === 'GET' && pathname === '/api/health') {
    const history = store.listHistory({ limit: 1000 });
    const last = history[0] || null;

    // P0 — report capability health, not just liveness. A scan running without
    // a renderer produces *inflated* scores, so the server must say so loudly
    // rather than silently returning `ok: true`.
    const render = integrity.probeRenderCapability({ fresh: q.get('fresh') === '1' });

    return sendJson(res, 200, {
      ok: true,
      // Tells the UI whether it must supply a token. Deliberately does NOT leak
      // the token itself — just whether one is required, so the page can prompt
      // up-front instead of failing on the first scan.
      auth: !ALLOW_INSECURE && !!API_TOKEN,
      scans: history.length,
      lastScan: last ? { id: last.id, target: last.target, score: last.score, at: last.at } : null,
      queue: queue.stats(),
      capabilities: {
        render: {
          ok: render.ok,
          capability: integrity.RENDER_CAPABILITY,
          path: render.path,
          error: render.error,
          hint: render.hint,
          affects: ['performance', 'accessibility(rendered)'],
          effect: render.ok ? null : 'perf + rendered-a11y checks do not run; scores are capped',
        },
        pentest: {
          ok: nuclei.isAvailable(),
          capability: 'nuclei-dast',
          path: nuclei.NUCLEI_BIN || 'nuclei',
        },
      },
      // Convenience roll-up: false when the tool cannot fully verify a site.
      fullFidelity: render.ok,
    });
  }

  if (req.method === 'GET' && pathname === '/api/history') {
    const limit = Math.min(parseInt(q.get('limit'), 10) || 50, 500);
    return sendJson(res, 200, { history: store.listHistory({ target: q.get('target'), limit }) });
  }

  if (req.method === 'GET' && pathname === '/api/jobs') {
    return sendJson(res, 200, { jobs: queue.list(parseInt(q.get('limit'), 10) || 25), stats: queue.stats() });
  }

  // Portfolio: latest scan per target, ranked worst-first (Phase 8).
  if (req.method === 'GET' && pathname === '/api/portfolio') {
    const history = store.listHistory({ limit: 1000 });
    const byTarget = new Map();
    for (const h of history) {
      const key = h.targetKey || h.target;
      const hit = byTarget.get(key);
      if (!hit) { byTarget.set(key, { latest: h, scans: 1 }); continue; }
      hit.scans++;
      if ((h.at || '') > (hit.latest.at || '')) hit.latest = h;
    }
    const targets = [...byTarget.entries()].map(([key, v]) => ({
      targetKey: key,
      target: v.latest.target,
      finalUrl: v.latest.finalUrl,
      score: v.latest.score,
      grade: v.latest.grade,
      counts: v.latest.counts,
      at: v.latest.at,
      scans: v.scans,
      reportId: v.latest.id,
    }));
    targets.sort((a, b) => (a.score ?? 999) - (b.score ?? 999));
    return sendJson(res, 200, { targets });
  }

  // Queue a list of URLs to scan sequentially (portfolio batch).
  if (req.method === 'POST' && pathname === '/api/scan/portfolio') {
    let payload;
    try {
      payload = JSON.parse(await readBody(req) || '{}');
    } catch (e) {
      return sendJson(res, 400, { error: 'Invalid JSON body' });
    }
    const urls = (Array.isArray(payload.urls) ? payload.urls : String(payload.urls || '').split(/[\s,]+/))
      .map((u) => String(u).trim())
      .filter(Boolean)
      .slice(0, 25);
    if (!urls.length) return sendJson(res, 400, { error: 'Missing "urls"' });
    const jobs = urls.map((u) => queue.enqueue(u, {
      deep: payload.deep !== false,
      performance: payload.performance,
    }));
    return sendJson(res, 202, { queued: jobs.length, jobs, poll: '/api/jobs' });
  }

  if (req.method === 'GET' && pathname.startsWith('/api/jobs/')) {
    const id = safeDecode(pathname.slice('/api/jobs/'.length));
    if (!validId(id)) return sendJson(res, 400, { error: 'Invalid job id' });
    const job = queue.get(id);
    if (!job) return sendJson(res, 404, { error: 'Job not found' });
    return sendJson(res, 200, job);
  }

  if (req.method === 'GET' && pathname.startsWith('/api/report/')) {
    const rest = safeDecode(pathname.slice('/api/report/'.length));
    if (rest == null) return sendJson(res, 400, { error: 'Invalid report id' });
    const [id, tail] = rest.split('/');
    if (!validId(id)) return sendJson(res, 400, { error: 'Invalid report id' });
    const report = store.getReport(id);
    if (!report) return sendJson(res, 404, { error: 'Report not found' });
    if (tail === 'diff') {
      const list = store.listHistory({ limit: 1000 });
      const idx = list.findIndex((h) => h.id === id);
      const previousSummary = idx >= 0 ? list[idx + 1] : null;
      const previous = previousSummary ? store.getReport(previousSummary.id) : null;
      return sendJson(res, 200, diffReports(previous, report));
    }
    return sendJson(res, 200, report);
  }

  if (req.method === 'GET' && pathname.startsWith('/api/export/')) {
    const rest = safeDecode(pathname.slice('/api/export/'.length));
    const m = rest && rest.match(/^([^/]+)\.(json|md|html|sarif)$/);
    if (!m) return sendJson(res, 400, { error: 'Use /api/export/<id>.(json|md|html|sarif)' });
    const [, id, ext] = m;
    if (!validId(id)) return sendJson(res, 400, { error: 'Invalid report id' });
    const report = store.getReport(id);
    if (!report) return sendJson(res, 404, { error: 'Report not found' });
    const list = store.listHistory({ limit: 1000 });
    const idx = list.findIndex((h) => h.id === id);
    const previousSummary = idx >= 0 ? list[idx + 1] : null;
    const previous = previousSummary ? store.getReport(previousSummary.id) : null;
    const diff = previous ? diffReports(previous, report) : diffReports(null, report);
    const slug = (report.targetKey || report.target || 'scan').replace(/[^A-Za-z0-9._-]+/g, '_');
    const base = `vibescan-${slug}-${id}`;
    if (ext === 'json') return sendText(res, 200, JSON.stringify({ report, diff }, null, 2), 'application/json', base + '.json');
    if (ext === 'md') return sendText(res, 200, exporters.toMarkdown(report, diff), 'text/markdown', base + '.md');
    if (ext === 'sarif') return sendText(res, 200, JSON.stringify(exporters.toSarif(report), null, 2), 'application/sarif+json', base + '.sarif');
    return sendText(res, 200, exporters.toHtml(report, diff), 'text/html', base + '.html');
  }

  if (req.method === 'POST' && pathname === '/api/scan') {
    let payload;
    try {
      payload = JSON.parse(await readBody(req) || '{}');
    } catch (e) {
      return sendJson(res, 400, { error: 'Invalid JSON body' });
    }
    const url = (payload.url || '').toString().trim();
    if (!url) return sendJson(res, 400, { error: 'Missing "url"' });
    if (url.length > 2048) return sendJson(res, 400, { error: 'URL too long' });

    const scanOptions = {
      profile: payload.profile,
      pentest: payload.pentest || payload.profile === 'pentest',
      nucleiTags: payload.nucleiTags,
      nucleiSeverity: payload.nucleiSeverity,
      deep: payload.deep !== false,
      maxPages: payload.maxPages,
      maxDepth: payload.maxDepth,
      performance: payload.performance,
      headers: sanitizeHeaders(payload.headers),
    };

    try {
      const report = await runAndStore(url, scanOptions);
      return sendJson(res, 200, report);
    } catch (e) {
      return sendJson(res, 422, { error: e.message });
    }
  }

  // Non-blocking: queue the scan and return a job handle the caller can poll.
  if (req.method === 'POST' && pathname === '/api/scan/async') {
    let payload;
    try {
      payload = JSON.parse(await readBody(req) || '{}');
    } catch (e) {
      return sendJson(res, 400, { error: 'Invalid JSON body' });
    }
    const url = (payload.url || '').toString().trim();
    if (!url) return sendJson(res, 400, { error: 'Missing "url"' });
    if (url.length > 2048) return sendJson(res, 400, { error: 'URL too long' });
    const job = queue.enqueue(url, {
      profile: payload.profile,
      pentest: payload.pentest || payload.profile === 'pentest',
      nucleiTags: payload.nucleiTags,
      nucleiSeverity: payload.nucleiSeverity,
      deep: payload.deep !== false,
      maxPages: payload.maxPages,
      maxDepth: payload.maxDepth,
      performance: payload.performance,
      headers: sanitizeHeaders(payload.headers),
    });
    return sendJson(res, 202, { job, poll: `/api/jobs/${job.id}` });
  }

  // White-box local source code security audit (e.g. ~/my-project)
  if (req.method === 'POST' && pathname === '/api/audit/local') {
    let payload;
    try {
      payload = JSON.parse(await readBody(req) || '{}');
    } catch (e) {
      return sendJson(res, 400, { error: 'Invalid JSON body' });
    }
    let targetPath = (payload.path || payload.url || '').toString().trim();
    if (!targetPath) return sendJson(res, 400, { error: 'Missing "path"' });
    if (targetPath.startsWith('~')) {
      targetPath = path.join(process.env.HOME || os.homedir(), targetPath.slice(1));
    }
    targetPath = path.resolve(targetPath);
    if (!fs.existsSync(targetPath)) {
      return sendJson(res, 404, { error: `Directory not found: ${targetPath}` });
    }
    try {
      const stat = fs.statSync(targetPath);
      if (!stat.isDirectory()) {
        return sendJson(res, 400, { error: `Path is not a directory: ${targetPath}` });
      }
    } catch (e) {
      return sendJson(res, 400, { error: `Unable to access directory: ${e.message}` });
    }

    try {
      const report = await runLocalSourceAudit(targetPath);
      const meta = store.saveReport(report);
      const { previous } = store.lastTwoFor(report.finalUrl || report.target);
      const diff = previous ? diffReports(previous, report) : diffReports(null, report);
      report.id = meta.id;
      report.targetKey = meta.targetKey;
      report.diff = diff;
      return sendJson(res, 200, report);
    } catch (e) {
      return sendJson(res, 500, { error: e.message });
    }
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    return serveStatic(res, pathname);
  }

  return sendJson(res, 405, { error: 'Method not allowed' });
}

// Last-resort safety net: an internal tool should degrade (log + keep serving)
// rather than die on an odd scan result or a malformed request. Without this,
// any stray throw inside the async request listener crashed the process.
process.on('uncaughtException', (err) => {
  console.error('[vibescan] uncaught exception:', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[vibescan] unhandled rejection:', reason && reason.stack ? reason.stack : reason);
});

// P0 — refuse to expose reports (un-redacted secrets/PII) without a token.
// Checked BEFORE binding so we fail fast without half-starting a listener.
if (BINDS_PUBLICLY && !API_TOKEN && !ALLOW_INSECURE) {
  console.error('──────────────────────────────────────────────────────────────');
  console.error(`[refusing to start] HOST=${HOST} exposes this server beyond loopback,`);
  console.error('but VIBESCAN_TOKEN is not set.');
  console.error('Reports are stored un-redacted (secrets + PII), so binding publicly');
  console.error('without auth would leak them to anyone on the network.');
  console.error('');
  console.error('  Fix one of:');
  console.error('    • unset HOST           → loopback-only (default, safest)');
  console.error('    • VIBESCAN_TOKEN=$(openssl rand -hex 32) HOST=0.0.0.0 node server.js');
  console.error('    • VIBESCAN_ALLOW_INSECURE=1 HOST=0.0.0.0 node server.js   (no auth — DANGEROUS)');
  console.error('──────────────────────────────────────────────────────────────');
  process.exit(1);
}

server.listen(PORT, HOST, () => {
  console.log(`VibeScan listening on http://${HOST}:${PORT}`);
  console.log(`Reports: ${store.REPORTS_DIR}`);

  // P0 — announce capability status at startup. Previously a missing browser was
  // only discoverable by noticing that perf scores were suspiciously absent.
  const render = integrity.probeRenderCapability({ fresh: true });
  if (BINDS_PUBLICLY && ALLOW_INSECURE) {
    console.warn('══════════════════════════════════════════════════════════════');
    console.warn(`[SECURITY] RUNNING WITHOUT AUTH on ${HOST}:${PORT} (VIBESCAN_ALLOW_INSECURE=1)`);
    console.warn('  Anyone who can reach this port (your LAN, and anyone on your');
    console.warn('  Tailscale tailnet) can read every stored report — which include');
    console.warn('  un-redacted secrets and PII — and can start scans.');
    console.warn('  Do not do this on an untrusted network. Set VIBESCAN_TOKEN instead.');
    console.warn('══════════════════════════════════════════════════════════════');
  } else if (API_TOKEN) {
    console.log(`[auth] token required for /api/* (VIBESCAN_TOKEN set, HOST=${HOST})`);
  } else {
    console.log(`[auth] loopback-only bind (${HOST}) — no token required`);
  }

  if (render.ok) {
    console.log(`[capabilities] headless render: OK (${render.path})`);
  } else {
    console.warn('──────────────────────────────────────────────────────────────');
    console.warn('[capabilities] headless render: UNAVAILABLE');
    console.warn(`  ${render.error}`);
    console.warn(`  ${render.hint}`);
    console.warn(`  → performance + rendered-a11y checks will NOT run.`);
    console.warn(`  → affected scans are marked "degraded" and capped at ${integrity.DEGRADED_SCORE_CAP}.`);
    console.warn('──────────────────────────────────────────────────────────────');
  }
});

function gracefulShutdown(signal) {
  console.log(`[vibescan] received ${signal}, shutting down workers...`);
  try { queue.shutdown(); } catch (_) {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = { server, runAndStore };
