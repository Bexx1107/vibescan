'use strict';
/**
 * Leaderboard HTTP layer (PLAN-LEADERBOARD.md §5).
 *
 * Mounted from server.js as `leaderboard.handle(req, res, ctx)` BEFORE the
 * generic /api routes. It only claims paths under /api/leaderboard*, so it
 * cannot shadow anything else.
 *
 * SECURITY NOTES (PLAN §2.1)
 *   • Nothing here returns raw scan evidence. Findings are reduced to
 *     id/title/severity, and `meta.build` is reduced to a boolean hint.
 *   • IPs are stored only as sha256(ip + in-memory daily salt).
 *   • Public deployments must set VIBESCAN_PUBLIC=1: this turns on the
 *     rate limiter and refuses deep/active scan options for anonymous
 *     submissions (passive GET/HEAD only).
 */

const crypto = require('crypto');
const db = require('./db');
const integrity = require('./integrity');
const verify = require('./verify');
const moderation = require('./moderation');
const favicon = require('./favicon');

/* ------------------------------------------------------------------ *
 * IP hashing — rotating in-memory salt, never persisted, never logged
 * ------------------------------------------------------------------ */

let salt = crypto.randomBytes(32);
let saltDay = new Date().toISOString().slice(0, 10);

function rotateSaltIfNeeded() {
  const today = new Date().toISOString().slice(0, 10);
  if (today !== saltDay) {
    salt = crypto.randomBytes(32);
    saltDay = today;
  }
}

// Where the client IP may come from, in priority order.
//
// Behind Caddy, `socket.remoteAddress` is always 127.0.0.1, so the proxy hop has
// to supply the real address. We trust exactly ONE header — `X-Real-IP`, which
// Caddy sets with `header_up X-Real-IP {remote_host}` and which it overwrites
// rather than appends. We deliberately do NOT read `X-Forwarded-For`: its
// left-most element is attacker-controlled, so rate limits keyed on it are
// bypassed by sending one header. Only if nothing else is available do we fall
// back to the socket address, which makes local/direct use still work.
function trustedIp(req) {
  const real = String(req.headers['x-real-ip'] || '').trim();
  if (real) return real;
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function ipHash(req) {
  rotateSaltIfNeeded();
  const raw = trustedIp(req);
  return crypto.createHash('sha256').update(raw).update(salt).digest('hex').slice(0, 32);
}

/* ------------------------------------------------------------------ *
 * In-memory token bucket (single process — the public instance is one box)
 * ------------------------------------------------------------------ */

const BUCKETS = new Map();
const LIMITS = {
  submit: { max: 10, windowMs: 60 * 60 * 1000 },   // 10 submissions / hour / IP
  claim: { max: 30, windowMs: 60 * 60 * 1000 },
  vote: { max: 60, windowMs: 60 * 60 * 1000 },
};

function allow(bucket, key) {
  const limit = LIMITS[bucket];
  const now = Date.now();
  const k = bucket + ':' + key;
  const rec = BUCKETS.get(k);
  if (!rec || now - rec.start > limit.windowMs) {
    BUCKETS.set(k, { start: now, count: 1 });
    return true;
  }
  if (rec.count >= limit.max) return false;
  rec.count++;
  return true;
}

// Bounded memory: drop expired buckets whenever the map grows large.
function gcBuckets() {
  if (BUCKETS.size < 5000) return;
  const now = Date.now();
  const maxWindow = Math.max(...Object.values(LIMITS).map((l) => l.windowMs));
  for (const [k, v] of BUCKETS) if (now - v.start > maxWindow) BUCKETS.delete(k);
}

/* ------------------------------------------------------------------ *
 * Validation
 * ------------------------------------------------------------------ */

const KINDS = new Set(['agency', 'solo', 'inhouse', 'ai', 'unknown']);
const PLATFORMS = new Set([
  'wordpress', 'shopify', 'wix', 'squarespace', 'webflow',
  'nextjs', 'nuxt', 'astro', 'custom', 'unknown',
]);
const VIEWS = new Set(['top', 'worst', 'recent', 'harness', 'model', 'agency', 'disputed', 'slop']);

function str(v, max) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s ? s.slice(0, max) : null;
}

/** Reject anything that is not an http(s) URL with a real public hostname. */
function validTarget(input) {
  const raw = str(input, 2048);
  if (!raw) return null;
  const withScheme = /^https?:\/\//i.test(raw) ? raw : 'https://' + raw;
  try {
    const u = new URL(withScheme);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (!db.normaliseHost(u.href)) return null;
    return u.href;
  } catch {
    return null;
  }
}

/**
 * Ephemeral deep report returned ONLY to the active browser session that
 * initiated the scan (`GET /api/leaderboard/job/:id`).
 * Never persisted to disk or SQLite — public DB stores only 1–100 numbers.
 */
function publicReport(report) {
  const m = report.meta || {};
  const deg = (report.degraded && report.degraded.degraded)
    ? report.degraded
    : (m.degraded && m.degraded.degraded ? m.degraded : null);
  return {
    target: report.target,
    finalUrl: report.finalUrl,
    resolvedIp: report.resolvedIp || null,
    status: report.status || (m.wire && m.wire.status) || 200,
    startedAt: report.startedAt,
    durationMs: report.durationMs,
    score: report.score,
    grade: report.grade,
    scoreCeiling: report.scoreCeiling || 100,
    scoreUncapped: typeof report.scoreUncapped === 'number' ? report.scoreUncapped : null,
    domainAverage: report.domainAverage || report.score,
    degraded: deg
      ? {
          degraded: true,
          kind: deg.kind || integrity.degradedKind(deg) || (m.isWafChallenge ? 'waf' : 'partial'),
          capabilities: Array.isArray(deg.capabilities) ? deg.capabilities : [],
          reason: deg.reason || null,
          hint: deg.hint || null,
          scoreCap: typeof deg.scoreCap === 'number' ? deg.scoreCap : null,
          unrunChecks: Array.isArray(deg.unrunChecks) ? deg.unrunChecks : [],
          wafProvider: m.wafProvider || null,
        }
      : null,
    counts: report.counts || {},
    domains: report.domains || {},
    ephemeralOnly: true,
    telemetry: {
      wire: m.wire || null,
      tls: m.tls || null,
      dns: m.dns || null,
      cwv: m.cwv || null,
      shodan: m.shodan || null,
      crux: m.crux || null,
      ct: m.ct || null,
      tech: m.tech || [],
      crawledPages: m.crawledPages || 1,
      scriptCount: m.scriptCount || 0,
      linksChecked: m.linksChecked || 0,
      build: m.build
        ? {
            platform: m.build.platform || null,
            generator: m.build.generator || null,
            credits: m.build.credits || [],
          }
        : null,
    },
    findings: (report.findings || []).map((f) => ({
      id: f.id,
      domain: f.domain,
      severity: f.severity,
      title: f.title,
      detail: f.detail || null,
      fix: f.fix || null,
      evidence: f.evidence ? String(f.evidence).slice(0, 1600) : null,
      whatItIs: f.whatItIs || null,
      impact: f.impact || null,
      worstCase: f.worstCase || null,
    })),
  };
}

/* ------------------------------------------------------------------ *
 * Handlers
 * ------------------------------------------------------------------ */

function listLeaderboard(q, ctx) {
  const view = VIEWS.has(q.get('view')) ? q.get('view') : 'top';
  const scope = q.get('scope') === 'si' ? 'si' : 'all';
  const limit = Math.min(Math.max(parseInt(q.get('limit'), 10) || 50, 1), 200);

  if (['harness', 'model', 'agency'].includes(view)) {
    const field = view === 'agency' ? 'builder_name' : view;
    return { view, scope, rows: db.cohort(field, limit, scope).map((r) => ({ ...r })) };
  }

  const conn = db.open();
  const scopeWhere = scope === 'si' ? " AND (s.host LIKE '%.si' OR s.host = 'si')" : '';
  let rows;
  if (view === 'recent') {
    rows = conn
      .prepare(
        `SELECT s.id, s.host, sc.score, sc.grade, sc.sec, sc.comp, sc.perf, sc.a11y, sc.seo, sc.quality, sc.at,
                sc.degraded, sc.degraded_reason, sc.score_cap
           FROM site s JOIN scan sc ON sc.id = s.latest_scan
          WHERE s.status = 'listed'${scopeWhere} ORDER BY sc.at DESC LIMIT ?`
      )
      .all(limit);
  } else if (view === 'worst' || view === 'slop') {
    rows = conn
      .prepare(
        `SELECT s.id, s.host, sc.score, sc.grade, sc.sec, sc.comp, sc.perf, sc.a11y, sc.seo, sc.quality, sc.at,
                sc.degraded, sc.degraded_reason, sc.score_cap
           FROM site s JOIN scan sc ON sc.id = s.latest_scan
          WHERE s.status = 'listed'${scopeWhere} ORDER BY sc.score ASC, sc.at DESC LIMIT ?`
      )
      .all(limit);
  } else if (view === 'disputed') {
    rows = conn
      .prepare(
        `SELECT s.id, s.host, sc.score, sc.grade, sc.sec, sc.comp, sc.perf, sc.a11y, sc.seo, sc.quality,
                sc.degraded, sc.degraded_reason, sc.score_cap,
                sub.builder_kind, sub.builder_name, sub.harness, sub.model,
                sub.verification, sub.created_at
           FROM submission sub
           JOIN site s ON s.id = sub.site_id AND s.status = 'listed'${scopeWhere}
           LEFT JOIN scan sc ON sc.id = s.latest_scan
          WHERE sub.verification = 'disputed'
          ORDER BY sub.created_at DESC LIMIT ?`
      )
      .all(limit);
  } else {
    rows = conn
      .prepare(
        `SELECT s.id, s.host, sc.score, sc.grade, sc.sec, sc.comp, sc.perf, sc.a11y, sc.seo, sc.quality, sc.at,
                sc.degraded, sc.degraded_reason, sc.score_cap
           FROM site s JOIN scan sc ON sc.id = s.latest_scan
          WHERE s.status = 'listed'${scopeWhere} ORDER BY sc.score DESC, sc.at DESC LIMIT ?`
      )
      .all(limit);
  }

  // Attach the newest provenance claim, but only the public-safe columns.
  const claimStmt = conn.prepare(
    `SELECT builder_kind, builder_name, platform, harness, model, verification,
            confidence, evidence_json, created_at
       FROM submission WHERE site_id = ? ORDER BY id DESC LIMIT 1`
  );
  const out = rows.map((r) => {
    const c = claimStmt.get(r.id);
    return {
      ...r,
      degraded: Boolean(r.degraded),
      degradedReason: r.degraded_reason || null,
      scoreCap: r.score_cap ?? null,
      claim: c
        ? {
            builderKind: c.builder_kind,
            builderName: c.builder_name,
            platform: c.platform,
            harness: c.harness,
            model: c.model,
            // harness/model are never verified — see lib/verify.js
            verification: c.verification,
            confidence: c.confidence,
            evidence: c.evidence_json ? JSON.parse(c.evidence_json) : [],
            createdAt: c.created_at,
          }
        : null,
    };
  });

  return { view, scope, rows: out, stats: db.stats() };
}

async function handle(req, res, ctx) {
  const { pathname, q } = ctx;
  if (!pathname.startsWith('/api/leaderboard')) return false;

  // `reply` writes the response and returns true so `handle()` can be used as
  // "did I handle this?" by the caller in server.js.
  const reply = (code, payload) => {
    ctx.sendJson(res, code, payload);
    return true;
  };

  const isPublic = process.env.VIBESCAN_PUBLIC === '1';
  const ip = ipHash(req);
  gcBuckets();

  /* ---------------- read-only views ---------------- */

  if (req.method === 'GET' && (pathname.startsWith('/api/leaderboard/favicon/') || pathname.startsWith('/api/favicon/'))) {
    favicon.serveFavicon(req, res, pathname, q);
    return true;
  }

  if (req.method === 'GET' && pathname === '/api/leaderboard') {
    return reply(200, listLeaderboard(q, ctx));
  }

  if (req.method === 'GET' && pathname === '/api/leaderboard/stats') {
    return reply(200, db.stats());
  }

  // Public-safe job polling. /api/jobs/:id and /api/report/:id are internal
  // (they carry meta, which includes detected secrets), so anonymous visitors
  // get this projection instead: status, then the public report summary.
  if (req.method === 'GET' && pathname.startsWith('/api/leaderboard/job/')) {
    const id = decodeURIComponent(pathname.slice('/api/leaderboard/job/'.length));
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/.test(id)) {
      return reply(400, { error: 'Invalid job id' });
    }
    const job = ctx.queue.get(id);
    if (!job) return reply(404, { error: 'Job not found' });

    if (job.status === 'done' && job.reportMeta) {
      const full =
        (typeof ctx.queue.getEphemeralReport === 'function' && ctx.queue.getEphemeralReport(job.reportMeta.id)) ||
        (ctx.store && ctx.store.getReport(job.reportMeta.id));
      if (!full) return reply(410, { error: 'Ephemeral deep report expired (not stored on server)' });
      const pub = publicReport(full);
      pub.hideResults = Boolean(job.hideResults || (job.options && job.options.hideResults));
      return reply(200, {
        status: 'done',
        reportId: job.reportMeta.id,
        report: pub,
      });
    }
    return reply(200, {
      status: job.status,
      error: job.error || null,
      progress: job.progress || null,
      queuePosition: job.queuePosition || 0,
    });
  }

  if (req.method === 'GET' && pathname.startsWith('/api/leaderboard/site/')) {
    const host = db.normaliseHost(decodeURIComponent(pathname.slice('/api/leaderboard/site/'.length)));
    if (!host) return reply(400, { error: 'Invalid host' });

    const conn = db.open();
    const site = conn.prepare('SELECT * FROM site WHERE host = ?').get(host);
    if (!site || site.status === 'removed') {
      return reply(404, { error: 'Site not listed' });
    }
    const scans = conn
      .prepare(
        `SELECT id, score, grade, sec, comp, perf, a11y, seo, quality, at,
                degraded, degraded_reason, score_cap
           FROM scan WHERE site_id = ? ORDER BY at DESC LIMIT 50`
      )
      .all(site.id)
      .map((s) => ({
        ...s,
        degraded: Boolean(s.degraded),
        degradedReason: s.degraded_reason || null,
        scoreCap: s.score_cap ?? null,
      }));
    const submissions = conn
      .prepare(
        `SELECT id, builder_kind, builder_name, platform, harness, model,
                verification, confidence, evidence_json, created_at
           FROM submission WHERE site_id = ? ORDER BY id DESC LIMIT 20`
      )
      .all(site.id)
      .map((s) => ({
        id: s.id,
        builderKind: s.builder_kind,
        builderName: s.builder_name,
        platform: s.platform,
        harness: s.harness,
        model: s.model,
        verification: s.verification,
        confidence: s.confidence,
        evidence: s.evidence_json ? JSON.parse(s.evidence_json) : [],
        createdAt: s.created_at,
      }));
    return reply(200, {
      host: site.host,
      url: site.url,
      status: site.status,
      firstSeen: site.first_seen,
      lastSeen: site.last_seen,
      scans,
      submissions,
    });
  }

  /* ---------------- writes ---------------- */

  if (req.method === 'POST' && pathname === '/api/leaderboard/submit') {
    if (isPublic && !allow('submit', ip)) {
      return reply(429, {
        error: 'Hourly scan limit reached (10 scans per hour). Please try again in a little while.',
        code: 'RATE_LIMITED',
        limit: 10,
        window: '1h',
      });
    }
    let payload;
    try {
      payload = await ctx.readBody(req).then((b) => JSON.parse(b || '{}'));
    } catch {
      return reply(400, { error: 'Invalid JSON body' });
    }
    const url = validTarget(payload.url);
    if (!url) return reply(400, { error: 'A public http(s) URL is required' });

    const hideResults = Boolean(payload.hideResults);
    const followRedirects = payload.followRedirects !== false;

    // Public instances are strictly passive: no active probes, no nuclei, no pentest profile.
    const scanOptions = {
      deep: true,
      fingerprint: true,
      pentest: false,
      skipActive: true,
      profile: 'default',
      headers: null,
      hideResults,
      followRedirects,
    };

    try {
      const job = ctx.queue.enqueue(url, scanOptions);
      return reply(202, { job, poll: `/api/jobs/${job.id}` });
    } catch (err) {
      if (err && err.code === 'QUEUE_FULL') {
        return reply(503, {
          error: 'Scanner queue is currently full. Please try again in a minute.',
          code: 'QUEUE_FULL',
        });
      }
      throw err;
    }
  }

  if (req.method === 'POST' && pathname === '/api/leaderboard/claim') {
    if (isPublic && !allow('claim', ip)) {
      return reply(429, {
        error: 'Too many claims, try again later',
        code: 'RATE_LIMITED',
      });
    }
    let payload;
    try {
      payload = await ctx.readBody(req).then((b) => JSON.parse(b || '{}'));
    } catch {
      return reply(400, { error: 'Invalid JSON body' });
    }

    const kind = str(payload.builderKind, 20);
    if (!KINDS.has(kind)) {
      return reply(400, { error: 'builderKind must be one of ' + [...KINDS].join(', ') });
    }
    const platform = str(payload.platform, 20);
    if (platform && !PLATFORMS.has(platform)) {
      return reply(400, { error: 'Unknown platform' });
    }

    const reportId = str(payload.reportId, 120);
    const report =
      (reportId && typeof ctx.queue.getEphemeralReport === 'function' && ctx.queue.getEphemeralReport(reportId)) ||
      (reportId && ctx.store && ctx.store.getReport(reportId));
    if (!reportId || !report) {
      return reply(404, { error: 'Unknown or expired reportId — scan the site first' });
    }
    const host = db.normaliseHost(report.finalUrl || report.target);
    if (!host) return reply(400, { error: 'Report has no public host' });

    const conn = db.open();
    const site = conn.prepare('SELECT * FROM site WHERE host = ?').get(host);
    if (!site || site.status === 'removed') {
      return reply(404, { error: 'Site not listed' });
    }

    const claim = {
      builderKind: kind,
      builderName: str(payload.builderName, 120),
      platform: platform || null,
      harness: str(payload.harness, 60),
      model: str(payload.model, 60),
    };

    const result = verify.verifyClaim(claim, report);

    const saved = db.recordSubmission({
      siteId: site.id,
      scanId: site.latest_scan,
      builderKind: claim.builderKind,
      builderName: claim.builderName,
      platform: result.platform || claim.platform,
      harness: claim.harness,
      model: claim.model,
      // Harness/model never affect this value; it is the verdict on the
      // verifiable fields only.
      verification: result.verification,
      confidence: result.confidence,
      evidence: {
        notes: result.evidence.slice(0, 8),
        contradictions: result.contradictions,
        fields: result.fields,
        stackHint: result.stackHint,
      },
      ipHash: ip,
    });

    return reply(201, {
      id: saved.id,
      host,
      verification: result.verification,
      confidence: result.confidence,
      fields: result.fields,
      evidence: result.evidence,
      contradictions: result.contradictions,
      stackHint: result.stackHint,
    });
  }

  if (req.method === 'POST' && pathname === '/api/leaderboard/vote') {
    if (isPublic && !allow('vote', ip)) {
      return reply(429, {
        error: 'Too many votes, try again later',
        code: 'RATE_LIMITED',
      });
    }
    let payload;
    try {
      payload = await ctx.readBody(req).then((b) => JSON.parse(b || '{}'));
    } catch {
      return reply(400, { error: 'Invalid JSON body' });
    }
    const submissionId = parseInt(payload.submissionId, 10);
    const value = payload.value === 1 || payload.value === -1 ? payload.value : null;
    if (!Number.isInteger(submissionId) || value === null) {
      return reply(400, { error: 'submissionId and value (+1|-1) are required' });
    }

    const conn = db.open();
    const sub = conn.prepare('SELECT id, site_id FROM submission WHERE id = ?').get(submissionId);
    if (!sub) return reply(404, { error: 'Unknown submission' });

    try {
      conn
        .prepare(
          `INSERT INTO vote (site_id, submission, value, ip_hash, created_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (submission, ip_hash) DO UPDATE SET value = excluded.value`
        )
        .run(sub.site_id, submissionId, value, ip, new Date().toISOString());
    } catch (e) {
      return reply(500, { error: 'Vote failed' });
    }

    const tally = conn
      .prepare('SELECT SUM(value) AS score, COUNT(*) AS votes FROM vote WHERE submission = ?')
      .get(submissionId);
    return reply(200, { submissionId, tally });
  }

  // Ownership + removal live in lib/moderation.js so this file stays about
  // ranking. It returns false when it does not own the path.
  const handled = await moderation.handle({
    req,
    pathname,
    ipHash: ip,
    fetchImpl: ctx.fetchImpl,
    reply,
    readJson: async () => {
      try {
        return JSON.parse((await ctx.readBody(req)) || '{}');
      } catch {
        return null;
      }
    },
  });
  if (handled) return handled;

  return reply(404, { error: 'Unknown leaderboard route' });
}

module.exports = { handle, publicReport, validTarget, ipHash, LIMITS };
