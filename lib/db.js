'use strict';
/**
 * VibeScan leaderboard store — SQLite via the built-in `node:sqlite` module.
 *
 * Zero external dependencies (Node >= 22.5 ships `node:sqlite`; this machine
 * runs v25.9.0). See PLAN-LEADERBOARD.md §3.
 *
 * SECURITY CONTRACT (PLAN-LEADERBOARD.md §2.1) — read before adding a column:
 *   This database stores ONLY derived data: hosts, scores, sub-scores,
 *   finding ids/titles/severities, timestamps, provenance claims and votes.
 *   It must NEVER store raw HTML, response bodies, `evidence` payloads,
 *   cookies, tokens, credentials or PII. The internal scanner keeps those in
 *   data/reports/*.json, which the public instance does not read.
 *
 * The DB lives in its own directory so a public deployment can point at an
 * empty volume without touching the internal scanner's data:
 *   VIBESCAN_DB_DIR   (default: <repo>/data)
 *   VIBESCAN_DB_FILE  (default: vibescan.db inside VIBESCAN_DB_DIR)
 */

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DB_DIR = process.env.VIBESCAN_DB_DIR || path.join(__dirname, '..', 'data');
const DB_FILE = process.env.VIBESCAN_DB_FILE || path.join(DB_DIR, 'vibescan.db');

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS site (
  id          INTEGER PRIMARY KEY,
  host        TEXT NOT NULL UNIQUE,          -- lower, no www, no port
  url         TEXT NOT NULL,                 -- first submitted URL
  latest_scan INTEGER,                       -- drives every public query
  status      TEXT NOT NULL DEFAULT 'listed',-- listed|claimed|hidden|removed
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan (
  id          INTEGER PRIMARY KEY,
  site_id     INTEGER NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  report_id   TEXT NOT NULL,
  score       INTEGER NOT NULL,
  grade       TEXT NOT NULL,
  sec         INTEGER,
  comp        INTEGER,
  perf        INTEGER,
  a11y        INTEGER,
  seo         INTEGER,
  quality     INTEGER,
  counts_json TEXT,                          -- {"high":3,"medium":7,...}
  deep        INTEGER NOT NULL DEFAULT 0,    -- 1 = active probes were allowed
  duration_ms INTEGER,
  at          TEXT NOT NULL,
  degraded    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS submission (
  id           INTEGER PRIMARY KEY,
  site_id      INTEGER NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  scan_id      INTEGER REFERENCES scan(id) ON DELETE SET NULL,
  builder_kind TEXT NOT NULL,                -- agency|solo|inhouse|unknown|ai
  builder_name TEXT,
  platform     TEXT,                         -- wordpress|webflow|next|shopify|...
  harness      TEXT,                         -- stored, NEVER verified
  model        TEXT,                         -- stored, NEVER verified
  verification TEXT NOT NULL DEFAULT 'unverified', -- verified|disputed|unverified
  confidence   INTEGER,
  evidence_json TEXT,                        -- plain sentences, no payloads
  ip_hash      TEXT,                         -- sha256(ip+daily salt), rate limit only
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vote (
  id          INTEGER PRIMARY KEY,
  site_id     INTEGER NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  submission  INTEGER NOT NULL REFERENCES submission(id) ON DELETE CASCADE,
  value       INTEGER NOT NULL,              -- +1 / -1
  ip_hash     TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  UNIQUE (submission, ip_hash)
);

CREATE TABLE IF NOT EXISTS claim_request (
  id          INTEGER PRIMARY KEY,
  site_id     INTEGER NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  method      TEXT NOT NULL,                 -- dns-txt|file|github|email
  token       TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',
  created_at  TEXT NOT NULL,
  verified_at TEXT
);

CREATE TABLE IF NOT EXISTS removal_request (
  id         INTEGER PRIMARY KEY,
  site_id    INTEGER NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  reason     TEXT,
  email      TEXT,
  status     TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_site_at   ON scan(site_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_score     ON scan(score DESC);
CREATE INDEX IF NOT EXISTS idx_sub_site       ON submission(site_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sub_harness    ON submission(harness) WHERE harness IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sub_model      ON submission(model)   WHERE model   IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sub_verif      ON submission(verification);
CREATE INDEX IF NOT EXISTS idx_vote_site      ON vote(site_id);
CREATE INDEX IF NOT EXISTS idx_site_listed    ON site(status) WHERE status = 'listed';
`;

let db = null;

/** Open (and migrate) the database. Idempotent. */
function open() {
  if (db) return db;
  fs.mkdirSync(DB_DIR, { recursive: true, mode: 0o700 });
  db = new DatabaseSync(DB_FILE);
  db.exec(SCHEMA);
  try {
    db.exec('ALTER TABLE scan ADD COLUMN degraded INTEGER DEFAULT 0');
  } catch {
    /* column already exists */
  }
  try {
    fs.chmodSync(DB_FILE, 0o600);
  } catch {
    /* non-POSIX filesystem — harmless */
  }
  if (typeof db.transaction !== 'function') {
    db.transaction = function (fn) {
      return function (...args) {
        db.exec('BEGIN');
        try {
          const res = fn(...args);
          db.exec('COMMIT');
          return res;
        } catch (err) {
          try {
            db.exec('ROLLBACK');
          } catch {
            /* ignore rollback failure if transaction was not active */
          }
          throw err;
        }
      };
    };
  }
  return db;
}

function close() {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Normalise a URL or host into the leaderboard key: lower, no www, no port.
 * Returns '' for anything that is not a public web target — `local://`,
 * `file://`, IP-only and unparseable inputs are not leaderboard entries.
 */
function normaliseHost(input) {
  let raw = String(input || '').trim();
  if (!raw) return '';
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = 'https://' + raw;
  try {
    const u = new URL(raw);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    const host = u.hostname.toLowerCase().replace(/^www\./, '');
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) return ''; // no localhost, no bare IPs
    return host;
  } catch {
    return '';
  }
}

/**
 * Insert a scan, or update the existing site row so `latest_scan` points at
 * the newest one (PLAN §2.6: repeat submissions show only the newest scan).
 * Returns { siteId, scanId, isNewSite }.
 */
function recordScan(report, opts = {}) {
  const conn = open();
  const host = normaliseHost(report.finalUrl || report.target);
  if (!host) throw new Error('recordScan: unparseable target');
  const url = report.finalUrl || report.target;
  const at = report.startedAt || new Date().toISOString();
  const d = report.domains || {};
  const score = (k) => (d[k] && Number.isFinite(d[k].score) ? d[k].score : null);

  const tx = conn.prepare('SELECT id, status FROM site WHERE host = ?');
  const existing = tx.get(host);

  let siteId;
  let isNewSite = false;
  if (existing) {
    siteId = existing.id;
    // If the domain was previously removed from the leaderboard, a new explicit public scan
    // re-lists it with the fresh results.
    conn
      .prepare("UPDATE site SET last_seen = ?, url = ?, status = 'listed' WHERE id = ?")
      .run(at, url, siteId);
  } else {
    isNewSite = true;
    const r = conn
      .prepare(
        'INSERT INTO site (host, url, status, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)'
      )
      .run(host, url, 'listed', at, at);
    siteId =Number(r.lastInsertRowid);
  }

  const isDegraded = Boolean(
    report.degraded ||
    (report.meta && report.meta.degraded && report.meta.degraded.degraded) ||
    (report.findings && report.findings.some((f) => f.id === 'scan-degraded'))
  );

  const ins = conn
    .prepare(
      `INSERT INTO scan
         (site_id, report_id, score, grade, sec, comp, perf, a11y, seo, quality,
          counts_json, deep, duration_ms, at, degraded)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      siteId,
      '',
      Number(report.score) || 0,
      String(report.grade || '?'),
      score('security'),
      score('compliance'),
      score('performance'),
      score('accessibility'),
      score('seo'),
      score('quality'),
      null,
      opts.deep ? 1 : 0,
      Number.isFinite(report.durationMs) ? report.durationMs : null,
      at,
      isDegraded ? 1 : 0
    );

  const scanId = Number(ins.lastInsertRowid);

  // Integrity Protection: Never allow a degraded/incomplete scan (e.g. temporary WAF/bot challenge)
  // to overwrite an existing clean, verified scan on the public leaderboard.
  let updateLatest = true;
  if (isDegraded && existing && existing.latest_scan) {
    try {
      const prevScan = conn.prepare('SELECT degraded FROM scan WHERE id = ?').get(existing.latest_scan);
      if (prevScan && !prevScan.degraded) {
        updateLatest = false; // preserve the previous clean scan
      }
    } catch (_) {}
  }

  if (updateLatest) {
    conn.prepare('UPDATE site SET latest_scan = ? WHERE id = ?').run(scanId, siteId);
  }
  return { siteId, scanId, isNewSite, host, isDegraded, keptPreviousScan: !updateLatest };
}

/** Store a provenance claim. harness/model are recorded but never verified. */
function recordSubmission(input) {
  const conn = open();
  const now = new Date().toISOString();
  const r = conn
    .prepare(
      `INSERT INTO submission
         (site_id, scan_id, builder_kind, builder_name, platform, harness, model,
          verification, confidence, evidence_json, ip_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      input.siteId,
      input.scanId || null,
      input.builderKind || 'unknown',
      input.builderName || null,
      input.platform || null,
      input.harness || null,
      input.model || null,
      input.verification || 'unverified',
      Number.isFinite(input.confidence) ? input.confidence : null,
      input.evidence ? JSON.stringify(input.evidence) : null,
      input.ipHash || null,
      now
    );
  return { id: Number(r.lastInsertRowid), createdAt: now };
}

/** Newest scan per listed site — the shape every leaderboard view starts from. */
function latestListed(limit = 100) {
  const conn = open();
  return conn
    .prepare(
      `SELECT s.id, s.host, s.url, s.status, s.last_seen,
              sc.id AS scan_id, sc.score, sc.grade, sc.sec, sc.comp, sc.perf,
              sc.a11y, sc.seo, sc.quality, sc.counts_json, sc.deep, sc.at, sc.degraded
         FROM site s
         JOIN scan sc ON sc.id = s.latest_scan
        WHERE s.status = 'listed'
        ORDER BY sc.score DESC
        LIMIT ?`
    )
    .all(limit);
}

/**
 * Aggregate a cohort (harness / model / builder) using only the newest scan
 * per site and only the newest submission per site. Returns rows plus the
 * cohort size so the UI can gate on n >= 5 (PLAN §2.8).
 */
function cohort(field, limit = 50, scope = 'all') {
  if (!['harness', 'model', 'builder_name', 'platform', 'builder_kind'].includes(field)) {
    throw new Error('cohort: unsupported field ' + field);
  }
  const conn = open();
  const scopeClause = scope === 'si' ? " AND (s.host LIKE '%.si' OR s.host = 'si')" : '';
  const rows = conn
    .prepare(
      `WITH newest_sub AS (
         SELECT sub.*, ROW_NUMBER() OVER (PARTITION BY sub.site_id ORDER BY sub.id DESC) AS rn
           FROM submission sub
          WHERE sub.${field} IS NOT NULL AND sub.${field} <> ''
       )
       SELECT ns.${field} AS label,
              COUNT(*)    AS n,
              ROUND(AVG(sc.score), 1) AS avg_score,
              MIN(sc.score) AS min_score,
              MAX(sc.score) AS max_score
         FROM newest_sub ns
         JOIN site s ON s.id = ns.site_id AND s.status = 'listed'${scopeClause}
         JOIN scan sc ON sc.id = s.latest_scan
        WHERE ns.rn = 1
        GROUP BY ns.${field}
        ORDER BY avg_score DESC
        LIMIT ?`
    )
    .all(limit);
  return rows.map((r) => ({ ...r, eligible: r.n >= 5 }));
}

function stats() {
  const conn = open();
  const base = conn
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM site WHERE status = 'listed')                    AS sites,
         (SELECT COUNT(*) FROM site WHERE status = 'listed' AND (host LIKE '%.si' OR host = 'si')) AS sites_si,
         (SELECT COUNT(*) FROM scan)                                            AS scans,
         (SELECT COUNT(*) FROM submission)                                       AS submissions,
         (SELECT COUNT(*) FROM submission WHERE verification = 'verified')       AS verified,
         (SELECT COUNT(*) FROM submission WHERE verification = 'disputed')       AS disputed`
    )
    .get();
  return {
    ...base,
    sitesSi: base.sites_si,
  };
}

module.exports = {
  open,
  close,
  normaliseHost,
  recordScan,
  recordSubmission,
  latestListed,
  cohort,
  stats,
  DB_FILE,
  DB_DIR,
  _schema: SCHEMA,
};
