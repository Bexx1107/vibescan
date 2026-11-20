'use strict';
/**
 * Tests for ownership verification (PLAN-LEADERBOARD.md Phase 5).
 *
 *   node --test test/ownership.test.js
 *
 * No network: DNS and fetch are stubbed. The point is that a successful check
 * requires the EXACT token, and that every failure mode returns verified:false
 * rather than throwing.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const ownership = require('../lib/ownership');

const TOKEN = 'a'.repeat(32);
const HOST = 'example.si';

/**
 * Route by EXACT URL, with no prefix matching. A prefix rule like
 * `https://example.si/` would also swallow
 * `https://example.si/.well-known/vibescan.txt`, so `checkWellKnown` would
 * "find" the token in the homepage HTML and the wrong method would win.
 */
function fakeFetch(map) {
  return async (url) => {
    if (Object.prototype.hasOwnProperty.call(map, url)) {
      return { ok: true, status: 200, text: async () => map[url] };
    }
    return { ok: false, status: 404, text: async () => '' };
  };
}

test('token format is enforced', () => {
  assert.equal(ownership.tokenValid(TOKEN), true);
  assert.equal(ownership.tokenValid('nope'), false);
  assert.equal(ownership.tokenValid(TOKEN.toUpperCase()), false);
  assert.equal(ownership.tokenValid(null), false);
});

test('newToken is 32 hex chars and unique', () => {
  const a = ownership.newToken();
  const b = ownership.newToken();
  assert.match(a, /^[a-f0-9]{32}$/);
  assert.notEqual(a, b);
});

test('well-known file verifies only with the exact token', async () => {
  const ok = await ownership.checkWellKnown(
    HOST, TOKEN, fakeFetch({ 'https://example.si/.well-known/vibescan.txt': `vibescan-verify=${TOKEN}` })
  );
  assert.equal(ok.ok, true);

  const wrong = await ownership.checkWellKnown(
    HOST, TOKEN, fakeFetch({ 'https://example.si/.well-known/vibescan.txt': 'vibescan-verify=' + 'b'.repeat(32) })
  );
  assert.equal(wrong.ok, false);
});

test('meta tag verifies only with the exact token', async () => {
  const html = `<head><meta name="vibescan-verify" content="${TOKEN}"></head>`;
  const ok = await ownership.checkMetaTag(HOST, TOKEN, fakeFetch({ 'https://example.si/': html }));
  assert.equal(ok.ok, true);

  const wrong = await ownership.checkMetaTag(
    HOST, TOKEN, fakeFetch({ 'https://example.si/': '<meta name="vibescan-verify" content="' + 'c'.repeat(32) + '">' })
  );
  assert.equal(wrong.ok, false);
});

test('missing endpoints fail closed, never throw', async () => {
  const r = await ownership.checkWellKnown(HOST, TOKEN, fakeFetch({}));
  assert.equal(r.ok, false);
  assert.match(r.detail, /HTTP 404/);
});

test('verifyOwnership reports which method succeeded', async () => {
  const fetchImpl = fakeFetch({ 'https://example.si/': `<meta name="vibescan-verify" content="${TOKEN}">` });
  // DNS will genuinely fail for _vibescan.example.si; the meta tag then wins.
  const r = await ownership.verifyOwnership({ host: HOST, token: TOKEN, fetchImpl });
  assert.equal(r.verified, true);
  assert.equal(r.method, 'meta');
  assert.equal(r.results['dns-txt'].ok, false);
});

test('verifyOwnership rejects an invalid token without any network call', async () => {
  let called = false;
  const r = await ownership.verifyOwnership({
    host: HOST,
    token: 'bogus',
    fetchImpl: async () => {
      called = true;
      return { ok: true, text: async () => '' };
    },
  });
  assert.equal(r.verified, false);
  assert.equal(called, false);
});

test('expired tokens are rejected', () => {
  const old = new Date(Date.now() - ownership.TOKEN_TTL_MS - 1000).toISOString();
  const fresh = new Date().toISOString();
  assert.equal(ownership.expired(old), true);
  assert.equal(ownership.expired(fresh), false);
  assert.equal(ownership.expired('not-a-date'), true);
});
