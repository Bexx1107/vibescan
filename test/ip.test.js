'use strict';

/**
 * Rate limiting keys on a hash of the client IP. If that key can be chosen by
 * the caller, the limits are decorative. These tests pin the only two ways an
 * address may be obtained, so a future "let's also read X-Forwarded-For" patch
 * fails here instead of in production.
 */

const test = require('node:test');
const assert = require('node:assert');

const { ipHash } = require('../lib/leaderboard');

function req(headers = {}, socketAddr = '127.0.0.1') {
  return { headers, socket: { remoteAddress: socketAddr } };
}

test('X-Real-IP from the proxy is used', () => {
  const a = ipHash(req({ 'x-real-ip': '203.0.113.7' }));
  const b = ipHash(req({}, '203.0.113.7'));
  assert.strictEqual(a, b, 'proxied and direct clients must hash the same');
});

test('X-Forwarded-For is ignored even when present', () => {
  const plain = ipHash(req({}, '192.0.2.10'));
  const spoofed = ipHash(req({ 'x-forwarded-for': '1.2.3.4, 192.0.2.10' }, '192.0.2.10'));
  assert.strictEqual(spoofed, plain, 'left-most XFF is attacker-controlled');
});

test('X-Real-IP wins over a conflicting X-Forwarded-For', () => {
  const withReal = ipHash(req({ 'x-real-ip': '198.51.100.5', 'x-forwarded-for': '9.9.9.9' }));
  const realOnly = ipHash(req({ 'x-real-ip': '198.51.100.5' }));
  assert.strictEqual(withReal, realOnly);
});

test('socket address is the fallback when no header is present', () => {
  assert.strictEqual(ipHash(req({}, '192.0.2.33')), ipHash(req({}, '192.0.2.33')));
  assert.notStrictEqual(ipHash(req({}, '192.0.2.33')), ipHash(req({}, '192.0.2.34')));
});

test('the hash never contains the raw address', () => {
  const h = ipHash(req({ 'x-real-ip': '203.0.113.7' }));
  assert.match(h, /^[0-9a-f]{32}$/);
  assert.ok(!h.includes('203.0.113.7'));
});

test('an empty X-Real-IP falls through instead of keying everyone to ""', () => {
  const empty = ipHash(req({ 'x-real-ip': '   ' }, '192.0.2.44'));
  const socket = ipHash(req({}, '192.0.2.44'));
  assert.strictEqual(empty, socket);
});
