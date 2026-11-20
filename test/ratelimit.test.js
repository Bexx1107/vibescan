'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { handle, LIMITS } = require('../lib/leaderboard');

test('submit rate limiting returns structured 429 payload', async () => {
  const origEnv = process.env.VIBESCAN_PUBLIC;
  process.env.VIBESCAN_PUBLIC = '1';

  let capturedStatus = null;
  let capturedBody = null;

  const mockRes = {};

  const ip = '198.51.100.99';
  const req = {
    method: 'POST',
    headers: { 'x-real-ip': ip },
    socket: { remoteAddress: ip },
  };

  const ctx = {
    pathname: '/api/leaderboard/submit',
    q: {},
    sendJson(res, code, payload) {
      capturedStatus = code;
      capturedBody = payload;
    },
    queue: { enqueue: () => ({ id: 'mock-job-id' }) },
    readBody: async () => JSON.stringify({ url: 'https://example.com' }),
  };

  // Exhaust the limit (10)
  for (let i = 0; i < LIMITS.submit.max; i++) {
    await handle(req, mockRes, ctx);
  }

  // 11th request must be 429
  capturedStatus = null;
  capturedBody = null;
  await handle(req, mockRes, ctx);

  assert.strictEqual(capturedStatus, 429);
  assert.deepStrictEqual(capturedBody, {
    error: 'Hourly scan limit reached (10 scans per hour). Please try again in a little while.',
    code: 'RATE_LIMITED',
    limit: 10,
    window: '1h',
  });

  if (origEnv !== undefined) {
    process.env.VIBESCAN_PUBLIC = origEnv;
  } else {
    delete process.env.VIBESCAN_PUBLIC;
  }
});
