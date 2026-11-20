'use strict';
/**
 * Ownership + moderation routes (PLAN-LEADERBOARD.md §8, Phase 5).
 *
 * Kept out of lib/leaderboard.js so the public read paths stay easy to audit.
 * Mounted from leaderboard.handle() for:
 *   POST /api/leaderboard/claim-request   start ownership verification
 *   POST /api/leaderboard/claim-confirm   finish it with the token
 *   POST /api/leaderboard/removal         request removal
 *
 * The removal route is intentionally trivially easy to use and hard to
 * automate-abuse: it never removes anything by itself, it only queues.
 */

const db = require('./db');
const ownership = require('./ownership');

function str(v, max) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s ? s.slice(0, max) : null;
}

/* ------------------------------------------------------------------ *
 * Simple per-IP limit for the moderation endpoints
 * ------------------------------------------------------------------ */

const HITS = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const rec = HITS.get(key);
  if (!rec || now - rec.start > windowMs) {
    HITS.set(key, { start: now, count: 1 });
    return false;
  }
  rec.count++;
  return rec.count > max;
}

/* ------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------ */

async function handle(ctx) {
  const { req, pathname, ipHash, fetchImpl, reply, readJson } = ctx;

  if (req.method === 'POST' && pathname === '/api/leaderboard/claim-request') {
    if (limited('claim-request:' + ipHash, 10, 60 * 60 * 1000)) {
      return reply(429, { error: 'Too many claim requests' });
    }
    const body = await readJson();
    if (!body) return reply(400, { error: 'Invalid JSON body' });

    const host = db.normaliseHost(body.host || '');
    if (!host) return reply(400, { error: 'Invalid host' });

    const conn = db.open();
    const site = conn.prepare('SELECT id, status FROM site WHERE host = ?').get(host);
    if (!site) return reply(404, { error: 'Site not listed' });
    if (site.status === 'removed') return reply(410, { error: 'Site was removed' });

    const token = ownership.newToken();
    conn
      .prepare(
        `INSERT INTO claim_request (site_id, method, token, status, created_at)
         VALUES (?, ?, ?, 'pending', ?)`
      )
      .run(site.id, str(body.method, 20) || 'any', token, new Date().toISOString());

    return reply(201, {
      host,
      token,
      expiresInDays: Math.round(ownership.TOKEN_TTL_MS / 86400000),
      instructions: {
        'dns-txt': `Publish a TXT record at _vibescan.${host} containing "vibescan-verify=${token}".`,
        file: `Serve https://${host}/.well-known/vibescan.txt containing "${token}".`,
        meta: `Add <meta name="vibescan-verify" content="${token}"> to the homepage <head>.`,
      },
    });
  }

  if (req.method === 'POST' && pathname === '/api/leaderboard/claim-confirm') {
    if (limited('claim-confirm:' + ipHash, 20, 60 * 60 * 1000)) {
      return reply(429, { error: 'Too many attempts' });
    }
    const body = await readJson();
    if (!body) return reply(400, { error: 'Invalid JSON body' });

    const host = db.normaliseHost(body.host || '');
    const token = str(body.token, 40);
    if (!host || !ownership.tokenValid(token)) {
      return reply(400, { error: 'host and a valid token are required' });
    }

    const conn = db.open();
    const site = conn.prepare('SELECT id FROM site WHERE host = ?').get(host);
    if (!site) return reply(404, { error: 'Site not listed' });

    const request = conn
      .prepare(
        `SELECT * FROM claim_request
          WHERE site_id = ? AND token = ? AND status = 'pending'
          ORDER BY id DESC LIMIT 1`
      )
      .get(site.id, token);
    if (!request) return reply(404, { error: 'No pending request for that token' });
    if (ownership.expired(request.created_at)) {
      return reply(410, { error: 'Token expired, request a new one' });
    }

    const result = await ownership.verifyOwnership({ host, token, fetchImpl });
    if (!result.verified) {
      return reply(422, {
        error: 'Verification failed',
        detail: result.detail,
        attempts: result.results,
      });
    }

    conn
      .prepare("UPDATE claim_request SET status = 'verified', verified_at = ? WHERE id = ?")
      .run(new Date().toISOString(), request.id);
    conn.prepare("UPDATE site SET status = 'claimed' WHERE id = ?").run(site.id);

    return reply(200, { host, verified: true, method: result.method, detail: result.detail });
  }

  if (req.method === 'POST' && pathname === '/api/leaderboard/removal') {
    if (limited('removal:' + ipHash, 15, 60 * 60 * 1000)) {
      return reply(429, { error: 'Preveč zahtev. Poskusite kasneje.' });
    }
    const body = await readJson();
    if (!body) return reply(400, { error: 'Neveljavna zahteva' });

    const host = db.normaliseHost(body.host || '');
    if (!host) return reply(400, { error: 'Vnesite veljavno domeno' });

    const conn = db.open();
    const site = conn.prepare('SELECT id, status FROM site WHERE host = ?').get(host);
    if (!site) {
      // Proactively mark as removed so it is never listed on the public leaderboard
      conn.prepare(
        "INSERT INTO site (host, url, status, first_seen, last_seen) VALUES (?, ?, 'removed', ?, ?)"
      ).run(host, 'https://' + host, new Date().toISOString(), new Date().toISOString());
      return reply(200, {
        success: true,
        removed: true,
        host,
        message: 'Domena je bila takoj odstranjena iz javnega indeksa.'
      });
    }

    const runTx = typeof conn.transaction === 'function' ? conn.transaction.bind(conn) : (fn) => {
      return (...args) => {
        conn.exec('BEGIN');
        try {
          const res = fn(...args);
          conn.exec('COMMIT');
          return res;
        } catch (err) {
          try { conn.exec('ROLLBACK'); } catch {}
          throw err;
        }
      };
    };

    runTx(() => {
      conn.prepare('DELETE FROM submission WHERE site_id = ?').run(site.id);
      conn.prepare('DELETE FROM scan WHERE site_id = ?').run(site.id);
      conn.prepare('DELETE FROM vote WHERE site_id = ?').run(site.id);
      conn.prepare('DELETE FROM claim_request WHERE site_id = ?').run(site.id);
      conn.prepare('DELETE FROM removal_request WHERE site_id = ?').run(site.id);
      conn.prepare("UPDATE site SET status = 'removed', latest_scan = NULL WHERE id = ?").run(site.id);
    })();

    return reply(200, {
      success: true,
      removed: true,
      host,
      message: 'Domena je bila takoj odstranjena iz javnega indeksa.'
    });
  }

  return false;
}

module.exports = { handle };
