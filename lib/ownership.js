'use strict';
/**
 * Ownership verification (PLAN-LEADERBOARD.md §8, Phase 5).
 *
 * A site owner proves control of a host by publishing a token somewhere only
 * the owner can write. Three methods, all passive reads of public endpoints:
 *
 *   1. dns-txt  — TXT record `_vibescan.<host>` containing `vibescan-verify=<token>`
 *   2. file     — https://<host>/.well-known/vibescan.txt containing the token
 *   3. meta     — <meta name="vibescan-verify" content="<token>"> on the homepage
 *
 * Nothing here scans or probes beyond fetching a public URL / DNS record. The
 * token is random, single-use per site, and expires.
 */

const crypto = require('crypto');
const dns = require('dns').promises;

const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // a week is plenty
const TOKEN_RE = /^[a-f0-9]{32}$/;

function newToken() {
  return crypto.randomBytes(16).toString('hex');
}

function tokenValid(token) {
  return typeof token === 'string' && TOKEN_RE.test(token);
}

function expired(createdAt) {
  const then = new Date(createdAt).getTime();
  return !Number.isFinite(then) || Date.now() - then > TOKEN_TTL_MS;
}

/* ------------------------------------------------------------------ *
 * Method 1: DNS TXT
 * ------------------------------------------------------------------ */

async function checkDnsTxt(host, token) {
  try {
    const records = await dns.resolveTxt('_vibescan.' + host);
    // resolveTxt returns an array of chunk arrays.
    const flat = records.map((chunks) => chunks.join('')).join('\n');
    if (flat.includes('vibescan-verify=' + token)) {
      return { ok: true, detail: 'TXT record found at _vibescan.' + host };
    }
    return { ok: false, detail: 'No matching TXT record at _vibescan.' + host };
  } catch (err) {
    return { ok: false, detail: 'DNS lookup failed: ' + (err.code || err.message) };
  }
}

/* ------------------------------------------------------------------ *
 * Method 2: well-known file   Method 3: homepage meta tag
 * ------------------------------------------------------------------ */

async function fetchText(fetchImpl, url, limit = 64 * 1024) {
  const res = await fetchImpl(url, { redirect: 'follow' });
  if (!res || !res.ok) return { ok: false, detail: 'HTTP ' + (res ? res.status : 'error') };
  const body = await res.text();
  if (body.length > limit) return { ok: false, detail: 'response too large' };
  return { ok: true, body };
}

async function checkWellKnown(host, token, fetchImpl) {
  const url = 'https://' + host + '/.well-known/vibescan.txt';
  try {
    const r = await fetchText(fetchImpl, url);
    if (!r.ok) return { ok: false, detail: r.detail + ' at ' + url };
    if (r.body.includes(token)) return { ok: true, detail: 'Token found in ' + url };
    return { ok: false, detail: 'File exists but does not contain the token' };
  } catch (err) {
    return { ok: false, detail: 'Fetch failed: ' + err.message };
  }
}

async function checkMetaTag(host, token, fetchImpl) {
  const url = 'https://' + host + '/';
  try {
    const r = await fetchText(fetchImpl, url, 512 * 1024);
    if (!r.ok) return { ok: false, detail: r.detail + ' at ' + url };
    const re = /<meta[^>]+name\s*=\s*["']vibescan-verify["'][^>]+content\s*=\s*["']([a-f0-9]{32})["']/i;
    const m = r.body.match(re);
    if (m && m[1] === token) return { ok: true, detail: 'Meta tag found on the homepage' };
    return { ok: false, detail: 'No matching vibescan-verify meta tag' };
  } catch (err) {
    return { ok: false, detail: 'Fetch failed: ' + err.message };
  }
}

const METHODS = ['dns-txt', 'file', 'meta'];

/**
 * Try every method and return the first success.
 * @param {{host:string, token:string, fetchImpl?:Function}} opts
 */
async function verifyOwnership(opts) {
  const host = String(opts.host || '').toLowerCase();
  const token = opts.token;
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!host || !tokenValid(token)) {
    return { verified: false, detail: 'invalid host or token' };
  }

  const results = {};
  const checks = {
    'dns-txt': () => checkDnsTxt(host, token),
    file: () => checkWellKnown(host, token, fetchImpl),
    meta: () => checkMetaTag(host, token, fetchImpl),
  };

  for (const method of METHODS) {
    // eslint-disable-next-line no-await-in-loop
    const r = await checks[method]();
    results[method] = r;
    if (r.ok) return { verified: true, method, detail: r.detail, results };
  }
  return { verified: false, method: null, detail: 'No method succeeded', results };
}

module.exports = {
  newToken,
  tokenValid,
  expired,
  verifyOwnership,
  checkDnsTxt,
  checkWellKnown,
  checkMetaTag,
  METHODS,
  TOKEN_TTL_MS,
};
