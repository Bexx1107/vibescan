'use strict';

const test = require('node:test');
const assert = require('node:assert');
const webvitals = require('../lib/webvitals');

test('webvitals does not throw ReferenceError for host in launchChrome / measure', async () => {
  // Pass an invalid or localhost url that quickly resolves or rejects without ReferenceError: host is not defined
  try {
    const res = await webvitals.measure('http://127.0.0.1:65534', { timeoutMs: 1500 });
    // It should return an object (either { ok: false } or { ok: true }), never throw "host is not defined"
    assert.ok(typeof res === 'object');
    if (!res.ok) {
      assert.notStrictEqual(res.error, 'host is not defined');
    }
  } catch (err) {
    assert.fail(`Should not throw uncaught error: ${err.message}`);
  }
});
